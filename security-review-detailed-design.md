# 🔒 Security Review Agent — 详细设计说明书

> **⚠️ 已归档（2026-08-01）** — 早期设计稿，架构描述与实际实现（Claude Agent 编排 + `engine.py`）已脱节，仅作历史参考。实际能力见 [security-review/README.md](security-review/README.md)。

> **版本**：v1.0  
> **日期**：2026-07-27  
> **状态**：定稿  
> **定位**：通用安全审查 Agent 的详细技术设计方案  
> **依据**：security-review-requirements.md v2.0

---

## 目录

- [1. 系统架构](#1-系统架构)
- [2. 模块设计](#2-模块设计)
- [3. 数据模型](#3-数据模型)
- [4. 规则引擎](#4-规则引擎)
- [5. 扫描器实现](#5-扫描器实现)
- [6. 修复引擎](#6-修复引擎)
- [7. 报告与输出](#7-报告与输出)
- [8. CLI 与交互设计](#8-cli-与交互设计)
- [9. 异常处理与边界情况](#9-异常处理与边界情况)
- [10. 测试策略](#10-测试策略)
- [11. 开发序列](#11-开发序列)

---

## 1. 系统架构

### 1.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Claude Code Shell                              │
│  /security-review [options]                                         │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│  Skill Entry (security-review.md)                                   │
│  ├─ 解析 CLI 参数                                                   │
│  ├─ 执行 Phase 1-5 流程                                            │
│  └─ 协调子 Agent 并行扫描                                           │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│  Phase 1: Project Probe                    (单 Agent, 顺序)        │
│  ├─ 扫描文件树 → 识别技术栈                                         │
│  ├─ 读取关键配置文件                                                │
│  └─ 生成 ProbeResult → 确定加载规则集                               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│  Phase 2: Parallel Scan                    (多 Agent, 并行)        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Dependency│ │ Config   │ │ SAST     │ │ Auth     │ │ Business │  │
│  │ Scanner  │ │ Scanner  │ │ Scanner  │ │ Scanner  │ │ Scanner  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│  Phase 3: Aggregate & Dedup                 (单 Agent, 顺序)        │
│  ├─ 合并所有 Finding，去重                                           │
│  ├─ 按严重度排序                                                    │
│  └─ 交叉验证误报                                                    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│  Phase 4: Generate Fixes                    (单 Agent, 顺序)        │
│  ├─ 为每个可修复的 Finding 生成 Fix 方案                             │
│  └─ 生成 EditOperation 列表                                         │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│  Phase 5: Output Report                    (单 Agent, 顺序)        │
│  ├─ 生成终端摘要                                                    │
│  ├─ 生成详细发现列表                                                │
│  └─ 交互式修复入口                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 执行模式

有两种执行模式，Skill 根据参数选择：

**模式 A：全 Agent 编排（默认）**

Skill 使用 **Workflow** 工具编排多个子 Agent：

```
engine.py 不作为独立 Python 进程运行，而是作为 Claude Code 的
Workflow 脚本存在。每个 Phase 是一个 phase() 调用，
每个扫描器是一个 agent() 调用。
```

当不存在外部工具时，Agent 自身使用内置规则进行模式匹配，不需要 Python 运行时。

**模式 B：混合模式（`--quick`）**

仅执行 Phase 1 + Phase 2 中的 Config + Dependency 扫描，跳过 SAST、Auth、Business，适合快速检查。

### 1.3 技术选型

| 组件 | 选型 | 理由 |
|------|------|------|
| 技能定义 | `.claude/skills/security-review.md` | Claude Code 原生技能格式 |
| 子 Agent | `.claude/agents/*.md` | YAML frontmatter + Markdown 提示词 |
| 规则格式 | YAML | 人类可读、易于扩展、支持热加载 |
| 规则存放 | `rules/` 目录 | 独立于代码，可版本控制 |
| SAST 降级 | Python `sast_patterns.py` 内置模式库 | 无需外部依赖 |
| 依赖扫描降级 | Python 内置 CVE 对照表 | 离线可用 |
| 报告输出 | Markdown / JSON | 人类可读 + CI 可解析 |

---

## 2. 模块设计

### 2.1 项目结构

```
agent/security-review/
├── .claude/
│   ├── skills/
│   │   └── security-review.md          # 技能定义（入口点）
│   └── agents/
│       ├── dependency-scanner.md        # 依赖漏洞扫描 Agent
│       ├── config-scanner.md            # 配置安全扫描 Agent
│       ├── sast-scanner.md              # SAST 扫描 Agent
│       ├── auth-scanner.md              # 认证授权扫描 Agent
│       └── business-scanner.md          # 业务逻辑扫描 Agent
├── rules/                              # 安全规则 (YAML)
│   ├── base/
│   │   ├── secrets-in-code.yml
│   │   ├── weak-crypto.yml
│   │   └── debug-mode.yml
│   ├── python/
│   │   ├── sql-injection.yml
│   │   ├── command-injection.yml
│   │   ├── unsafe-deserialization.yml
│   │   ├── path-traversal.yml
│   │   └── ssrf.yml
│   ├── django/
│   │   ├── csrf.yml
│   │   ├── debug-true.yml
│   │   ├── allowed-hosts.yml
│   │   ├── cors.yml
│   │   └── secret-key.yml
│   ├── javascript/
│   │   ├── xss.yml
│   │   ├── prototype-pollution.yml
│   │   └── eval-usage.yml
│   ├── docker/
│   │   └── root-user.yml
│   └── cicd/
│       └── secrets-in-ci.yml
├── sast_patterns.py                    # 内置 SAST 模式库（降级用）
├── dependency_db.py                    # 内置 CVE 对照表（降级用）
├── models.py                           # 数据模型
├── utils.py                            # 通用工具函数
├── requirements.txt                    # 可选依赖
└── README.md                           # 文档
```

### 2.2 各模块职责

| 文件 | 角色 | 运行时 |
|------|------|--------|
| `.claude/skills/security-review.md` | 入口点，接收 CLI 参数，编排 5 个 Phase | Claude Code Skill |
| `.claude/agents/*-scanner.md` | 每个扫描维度一个 Agent，包含具体扫描指令和报告格式 | Claude Code Agent |
| `rules/**/*.yml` | YAML 规则文件，定义检测模式和修复方案 | 由 Agent 读取解析 |
| `sast_patterns.py` | 降级模式：Python 正则模式库 | Python 3.x |
| `dependency_db.py` | 降级模式：常见 CVE 对照表 | Python 3.x |
| `models.py` | Finding / Fix / Report 等数据类 | Python 3.x |
| `utils.py` | 文件读取、YAML 解析、颜色输出等工具 | Python 3.x |

---

## 3. 数据模型

### 3.1 核心类图

```
┌─────────────────────────────┐
│         Severity            │  (Enum)
├─────────────────────────────┤
│ CRITICAL                    │
│ HIGH                        │
│ MEDIUM                      │
│ LOW                         │
│ INFO                        │
└─────────────────────────────┘

┌─────────────────────────────┐
│       ScanDimension         │  (Enum)
├─────────────────────────────┤
│ DEPENDENCY                  │
│ CONFIG                      │
│ SAST                        │
│ AUTH                        │
│ BUSINESS                    │
└─────────────────────────────┘

┌─────────────────────────────────────────────────┐
│                   Finding                        │
├─────────────────────────────────────────────────┤
│ + id: str                            # 唯一标识  │
│ + dimension: ScanDimension           # 扫描维度  │
│ + severity: Severity                 # 严重度    │
│ + title: str                         # 标题      │
│ + description: str                   # 详细描述  │
│ + cwe: Optional[str]                 # CWE 编号  │
│ + owasp: Optional[str]               # OWASP 分类│
│ + file_path: Optional[str]           # 文件路径  │
│ + line: Optional[int]                # 行号      │
│ + code_snippet: Optional[str]        # 问题代码  │
│ + attack_scenario: Optional[str]     # 攻击场景  │
│ + fixes: List[Fix]                   # 修复方案  │
└─────────────────────┬───────────────────────────┘
                      │ 1
                      │ *
┌─────────────────────────────────────────────────┐
│                     Fix                          │
├─────────────────────────────────────────────────┤
│ + description: str                   # 修复说明  │
│ + type: str                          # 修复类型  │
│   "env_var" / "edit" / "config" /   │           │
│   "architectural"                    │           │
│ + effort: str                        # 工作量    │
│   "low" / "medium" / "high"         │           │
│ + edit_operations: List[EditOp]      # 编辑操作  │
└─────────────────────┬───────────────────────────┘
                      │ 1
                      │ *
┌─────────────────────────────────────────────────┐
│                  EditOperation                   │
├─────────────────────────────────────────────────┤
│ + file: str                          # 文件路径  │
│ + old_string: str                    # 原字符串  │
│ + new_string: str                    # 新字符串  │
│ + description: str                   # 操作说明  │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│                  Report                          │
├─────────────────────────────────────────────────┤
│ + project_name: str                  # 项目名称  │
│ + tech_stack: Dict[str, Any]         # 技术栈    │
│ + scan_time: float                   # 扫描耗时  │
│ + dimensions_covered: List[str]      # 覆盖维度  │
│ + findings: List[Finding]            # 发现列表  │
│ + total: int                         # 总计      │
│ + critical: int                      # 严重统计  │
│ + high: int                          │           │
│ + medium: int                        │           │
│ + low: int                           │           │
│ + auto_fixable: int                  # 可自动修复│
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│                 ProbeResult                      │
├─────────────────────────────────────────────────┤
│ + languages: List[str]               # 检测到的  │
│ + frameworks: List[str]              # 框架列表  │
│ + dep_managers: List[str]            # 依赖管理  │
│ + has_dockerfile: bool               │           │
│ + has_cicd: bool                     │           │
│ + config_files: Dict[str, str]       # 配置文件  │
│ + file_stats: Dict[str, int]         # 文件统计  │
│ + rules_to_load: List[str]           # 加载规则  │
└─────────────────────────────────────────────────┘
```

### 3.2 Python 实现

```python
# models.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        order = [self.CRITICAL, self.HIGH, self.MEDIUM, self.LOW, self.INFO]
        return order.index(self) < order.index(other)

    @property
    def emoji(self) -> str:
        return {
            self.CRITICAL: "🔴",
            self.HIGH: "🟠",
            self.MEDIUM: "🟡",
            self.LOW: "🟢",
            self.INFO: "⚪",
        }[self]


class ScanDimension(str, Enum):
    DEPENDENCY = "dependency"
    CONFIG = "config"
    SAST = "sast"
    AUTH = "auth"
    BUSINESS = "business"


@dataclass
class EditOperation:
    file: str
    old_string: str
    new_string: str
    description: str = ""


@dataclass
class Fix:
    description: str
    type: str  # "env_var" | "edit" | "config" | "architectural"
    effort: str = "medium"  # "low" | "medium" | "high"
    edit_operations: list[EditOperation] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    dimension: ScanDimension
    severity: Severity
    title: str
    description: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    attack_scenario: Optional[str] = None
    fixes: list[Fix] = field(default_factory=list)

    @property
    def is_auto_fixable(self) -> bool:
        return any(f.type in ("edit", "config", "env_var") for f in self.fixes)


@dataclass
class Report:
    project_name: str
    tech_stack: dict[str, Any]
    scan_time: float
    dimensions_covered: list[str]
    findings: list[Finding]

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def auto_fixable(self) -> int:
        return sum(1 for f in self.findings if f.is_auto_fixable)


@dataclass
class ProbeResult:
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    dep_managers: list[str] = field(default_factory=list)
    has_dockerfile: bool = False
    has_cicd: bool = False
    config_files: dict[str, str] = field(default_factory=dict)
    file_stats: dict[str, int] = field(default_factory=dict)
    rules_to_load: list[str] = field(default_factory=list)
```

### 3.3 YAML 规则格式

```yaml
# rules/django/csrf.yml
id: django-csrf-disabled          # 全局唯一 ID
name: CSRF Middleware Disabled    # 人类可读名称
description: >                   # 详细描述
  Detects when Django's CSRF middleware is
  commented out or missing from MIDDLEWARE list
severity: critical               # 严重度
cwe: CWE-352                     # 可选：CWE 编号
owasp: "A01:2021"               # 可选：OWASP 分类
languages: [python]              # 适用语言
frameworks: [django]             # 适用框架（可选）
tags: [config, csrf, django]     # 标签，用于过滤

# 检测规则（多个条件是 AND 关系）
detect:
  - type: file_not_contains
    path: "**/settings.py"
    pattern: "CsrfViewMiddleware"
  - type: file_contains
    path: "**/settings.py"
    pattern: "MIDDLEWARE"

# 修复方案（多个 fix 是 OR 关系，可任选）
fix:
  - type: uncomment               # 取消注释
    file: "**/settings.py"
    search: "#.*CsrfViewMiddleware"
    replacement: "    'django.middleware.csrf.CsrfViewMiddleware',"
  - type: insert_after            # 在指定锚点后插入
    file: "**/settings.py"
    anchor: "MIDDLEWARE = \\["
    text: "    'django.middleware.csrf.CsrfViewMiddleware',"
    position: after_opening_bracket
  - type: add_dependency          # 添加依赖
    manager: pip
    package: "django-cors-headers"
```

### 3.4 检测类型（detect 支持的类型）

| type | 参数 | 说明 |
|------|------|------|
| `file_contains` | path, pattern | 文件包含某模式 |
| `file_not_contains` | path, pattern | 文件不包含某模式 |
| `file_exists` | path | 文件存在 |
| `file_not_exists` | path | 文件不存在 |
| `line_matches` | path, pattern | 文件中有行匹配正则 |
| `line_not_matches` | path, pattern | 文件中没有行匹配正则 |
| `value_equals` | path, key, value | 配置文件中某 key 等于指定值 |
| `value_in_list` | path, key, values | 配置文件中某 key 在列表内 |
| `regex_in_file` | path, pattern, flags | 文件内容匹配正则可选标志 |
| `import_exists` | name, language | 代码中导入了某模块 |
| `dependency_vuln` | manager, package | 依赖中某包有已知漏洞 |

### 3.5 修复类型（fix 支持的类型）

| type | 参数 | 说明 |
|------|------|------|
| `edit` | file, old_string, new_string | 精确字符串替换 |
| `uncomment` | file, search, replacement | 取消注释 |
| `insert_after` | file, anchor, text, position | 在锚点后插入 |
| `insert_before` | file, anchor, text, position | 在锚点前插入 |
| `replace_line` | file, old, new | 替换整行 |
| `add_dependency` | manager, package, version | 添加依赖 |
| `remove_dependency` | manager, package | 删除依赖 |
| `replace_with_env_var` | file, key, env_var | 替换为环境变量引用 |
| `add_to_gitignore` | content | 添加到 .gitignore |

---

## 4. 规则引擎

### 4.1 规则加载流程

```
┌─────────────────────────────────────┐
│  ProbeResult.rules_to_load          │
│  = ["base", "python", "django",    │
│     "docker"]                       │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│  规则加载器 load_rules(categories)  │
│                                     │
│  1. 遍历 rules/{category}/*.yml     │
│  2. 解析 YAML ─→ Rule 对象         │
│  3. 按 languages/frameworks 过滤    │
│  4. 返回 List[Rule]                 │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│  规则匹配器 match_rules(rules, files)│
│                                     │
│  对每个 Rule：                       │
│  1. 展开 path glob → 匹配文件       │
│  2. 对每个 detect condition 检查    │
│  3. 所有 condition 通过 → Finding   │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│  输出 ─→ List[Finding]               │
└─────────────────────────────────────┘
```

### 4.2 规则解析（伪码）

```python
# utils.py
import yaml
import glob
import re
from pathlib import Path

class Rule:
    """已解析的规则"""
    def __init__(self, yaml_data: dict):
        self.id = yaml_data["id"]
        self.name = yaml_data["name"]
        self.description = yaml_data.get("description", "")
        self.severity = Severity(yaml_data["severity"])
        self.cwe = yaml_data.get("cwe")
        self.owasp = yaml_data.get("owasp")
        self.languages = yaml_data.get("languages", [])
        self.frameworks = yaml_data.get("frameworks", [])
        self.detect_conditions = yaml_data.get("detect", [])
        self.fix_suggestions = yaml_data.get("fix", [])
        self.tags = yaml_data.get("tags", [])

def load_rules(categories: list[str], rules_dir: str = "rules") -> list[Rule]:
    """从 YAML 文件加载规则"""
    rules = []
    for category in categories:
        pattern = Path(rules_dir) / category / "*.yml"
        for yaml_file in sorted(glob.glob(str(pattern))):
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
                if data:
                    rules.append(Rule(data))
    return rules
```

### 4.3 匹配逻辑（伪码）

```python
class ConditionMatcher:
    """执行 detect 条件匹配"""

    @staticmethod
    def check(condition: dict, files: dict[str, str]) -> bool:
        """检查单个条件，返回 True/False。files 是 {path: content} 的映射"""
        ctype = condition["type"]
        path_pattern = condition.get("path", "**/*")
        matched_files = _glob_files(path_pattern, files)

        if not matched_files:
            return False

        if ctype == "file_contains":
            return any(condition["pattern"] in content for content in matched_files.values())
        elif ctype == "file_not_contains":
            return all(condition["pattern"] not in content for content in matched_files.values())
        elif ctype == "line_matches":
            return any(
                re.search(condition["pattern"], content, re.MULTILINE)
                for content in matched_files.values()
            )
        elif ctype == "value_equals":
            return _check_config_value(matched_files, condition["key"], condition["value"])
        elif ctype == "regex_in_file":
            flags = condition.get("flags", 0)
            return any(re.search(condition["pattern"], content, flags) for content in matched_files.values())
        # ... 其他类型
        return False
```

### 4.4 规则优先级

```
base/              ← 最高优先级，始终加载
├── secrets-in-code.yml     (always)
├── weak-crypto.yml         (always)
└── debug-mode.yml          (always)

python/            ← 仅当检测到 Python
django/            ← 仅当检测到 Django
javascript/        ← 仅当检测到 JS/TS
express/           ← 仅当检测到 Express
go/                ← 仅当检测到 Go
java/              ← 仅当检测到 Java
docker/            ← 仅当检测到 Dockerfile
cicd/              ← 仅当检测到 CI/CD 配置

加载逻辑：
  1. 始终加载 rules/base/*
  2. 根据 ProbeResult.languages 加载 rules/{lang}/*
  3. 根据 ProbeResult.frameworks 加载 rules/{framework}/*
  4. 根据 ProbeResult.has_dockerfile 加载 rules/docker/*
  5. 根据 ProbeResult.has_cicd 加载 rules/cicd/*
```

---

## 5. 扫描器实现

### 5.1 依赖漏洞扫描器（Dependency Scanner）

**快速模式**（推荐，安装 pip-audit）：
```
Step 1: pip install pip-audit (如果未安装)
Step 2: pip-audit --json --desc on → 解析输出
Step 3: 如果 package-lock.json 存在 → npm audit --json → 解析输出
Step 4: 合并结果 → List[Finding]
```

**降级模式**（pip-audit 不可用）：
```
Step 1: pip list --format=json → 获取已安装包列表
Step 2: 对照 dependency_db.py 中的内置 CVE 表
Step 3: 正则匹配 package.json 中的依赖 → 对照 npm CVE 表
Step 4: 输出 → List[Finding]
```

**输出映射**：
```
pip-audit JSON → Finding
├── name+version  → title
├── vulns[].id    → cwe/cve
├── vulns[].description → description
├── fix_versions  → Fix.edit_operations (update requirements.txt)
└── severity      → Severity (根据 CVSS 分数或工具分类)
```

**内置 CVE 对照表**（`dependency_db.py`）:

```python
# 降级用：常见 Python 包的已知漏洞
# 格式：package_name → [(version_constraint, cve_id, severity, min_fixed_version)]
BUILTIN_CVE_DB_PYTHON = {
    "django": [
        ("<5.2.0", "CVE-2025-XXXXX", "high", "5.2.0"),
        ("<5.1.0", "CVE-2025-YYYYY", "critical", "5.1.0"),
    ],
    "sqlparse": [
        ("<0.5.6", "CVE-2024-XXXXX", "medium", "0.5.6"),
    ],
    # ... 定期更新
}

BUILTIN_CVE_DB_NPM = {
    "lodash": [
        ("<4.17.21", "CVE-2024-XXXXX", "critical", "4.17.21"),
    ],
    # ...
}
```

### 5.2 配置安全扫描器（Config Scanner）

纯粹基于 YAML 规则的模式匹配扫描，不需要外部工具。

**工作流程**：
```
1. 加载 ProdeResult 中确定的规则集
2. 对每个 Config 规则，执行 detect 条件
3. 匹配 → 生成 Finding
4. 根据 fix 定义生成 Fix
```

**针对 Django 的规则示例**：

| 规则文件 | 检测条件 | 检测方式 |
|----------|----------|----------|
| `csrf.yml` | `settings.py` 中缺少 `CsrfViewMiddleware` | 文件内容扫描 |
| `debug-true.yml` | `DEBUG=True` | 正则匹配 |
| `allowed-hosts.yml` | `ALLOWED_HOSTS=['*']` | 正则匹配 |
| `cors.yml` | `CORS_ALLOW_ALL_ORIGINS=True` | 正则匹配 |
| `secret-key.yml` | `SECRET_KEY` 为硬编码值 | 正则匹配 + 模式识别 |
| `session-cookie.yml` | 缺少 `SESSION_COOKIE_SECURE` | 文件内容扫描 |
| `database.yml` | `ENGINE: sqlite3` 用于生产 | 正则匹配 |

### 5.3 SAST 扫描器（SAST Scanner）

**首选模式**（安装 bandit/semgrep）：
```
pip install bandit
bandit -r . -f json → 解析输出 → 映射到 Finding
```

**降级模式**（使用内置 SAST 模式库 `sast_patterns.py`）：

```python
# sast_patterns.py
# 按 [语言][漏洞类型] 组织的正则模式库

SAST_PATTERNS = {
    # ── SQL 注入 ──
    "sql-injection": {
        "python": [
            (r'\.raw\(\s*f["\']', "Django raw query with f-string (SQLi)"),
            (r'cursor\.execute\(\s*f["\']', "Cursor execute with f-string (SQLi)"),
            (r"execute\([\"'].*\%[\(s%d]", "SQL execute with % formatting (SQLi)"),
            (r'\.extra\(\s*.*where\s*=\s*["\'].*\+', "extra() with concatenation"),
        ],
        "javascript": [
            (r'db\.\w+\.\$where\(\s*["\']\s*\+', "MongoDB $where with concatenation"),
            (r'sequelize\.query\(\s*["\'].*\+', "Sequelize raw query with concat"),
        ],
        "go": [
            (r'\.Raw\(\s*f["\']', "GORM raw query with f-string"),
            (r'\.Exec\(\s*f["\']', "SQL Exec with f-string"),
        ],
        "java": [
            (r'Statement\.executeQuery\(\s*["\']', "Raw Statement (use PreparedStatement)"),
            (r'\+\s*request\.getParameter', "SQL concat with request param"),
        ],
    },
    # ── 命令注入 ──
    "command-injection": {
        "python": [
            (r'os\.system\(\s*f["\']', "F-string in os.system()"),
            (r'subprocess\.\w+\(\s*f["\']', "F-string in subprocess call"),
            (r'subprocess\.\w+\([\"'].*\+.*(?:request|input|param)', "Subprocess with user input"),
        ],
        "javascript": [
            (r'exec\(\s*f["\']', "F-string in exec()"),
            (r'exec\(\s*["\']\.*\+.*(?:req\.|body\.|query\.)', "Exec with user input"),
            (r'spawn\(\s*["\'].*\+', "Spawn with concatenation"),
        ],
    },
    # ── 路径遍历 ──
    "path-traversal": {
        "python": [
            (r'open\(\s*os\.path\.join\([^)]*,\s*(?:request|user|input|filepath|filename)',
             "Path traversal risk in file open"),
        ],
        "javascript": [
            (r'res\.sendFile\(\s*(?:req\.|body\.|query\.)', "Path traversal in sendFile()"),
            (r'fs\.(?:readFile|writeFile|unlink|rename)\(\s*(?:req\.|body\.|query\.)',
             "Path traversal in fs operation"),
        ],
    },
    # ── XSS ──
    "xss": {
        "python": [
            (r'mark_safe\(', "mark_safe() used without escaping"),
            (r'\{\{.*\|safe\}\}', "Django template safe filter"),
        ],
        "javascript": [
            (r'dangerouslySetInnerHTML\s*=', "dangerouslySetInnerHTML used"),
            (r'\.innerHTML\s*=', "innerHTML assignment"),
            (r'v-html\s*=', "Vue v-html directive"),
        ],
    },
    # ── 不安全反序列化 ──
    "unsafe-deserialization": {
        "python": [
            (r'pickle\.loads?\s*\(', "Unsafe pickle deserialization"),
            (r'yaml\.load\(\s*(?!.*Loader=(?:SafeLoader|FullLoader))', "Unsafe yaml.load()"),
        ],
        "java": [
            (r'ObjectInputStream\.readObject\s*\(', "Unsafe Java deserialization"),
        ],
    },
    # ── SSRF ──
    "ssrf": {
        "python": [
            (r'requests\.(?:get|post|put|delete)\(\s*(?:request|body|query|input|url)',
             "User-controlled URL in request"),
        ],
        "javascript": [
            (r'fetch\(\s*(?:req\.|body\.|query\.)', "User-controlled URL in fetch"),
        ],
    },
    # ── eval ──
    "eval-usage": {
        "javascript": [
            (r'eval\(\s*', "eval() used"),
            (r'Function\(\s*["\']', "new Function() used (eval-like)"),
        ],
        "python": [
            (r'eval\(\s*', "eval() used"),
            (r'exec\(\s*', "exec() used"),
        ],
    },
}
```

### 5.4 认证授权扫描器（Auth Scanner）

不依赖正则匹配，而是通过分析代码结构发现模式。

**检测内容**：

| 检测项 | 检测方法 | 示例 |
|--------|----------|------|
| 无权限校验的 View | 查找 ViewSet/View 的 permission_classes | `permission_classes = [AllowAny]` |
| 缺少角色校验 | 管理员接口无 `is_staff` 或 `is_superuser` 检查 | `loadUser`、`changeIntegral` |
| 硬编码超级管理员 | 检查是否有硬编码的 admin 凭据 | `seed.py` 中的默认管理员 |
| 弱密码策略 | 检查 password validator 配置 | 只有长度 >= 6 |
| CSRF 豁免 | `@csrf_exempt` 装饰器 | 装饰器使用 |
| Token 传输不安全 | Token 在 URL/Header 中明文 | `HTTP_TOKEN` |
| 会话固定 | 登录后未销毁重建 session | `login()` 后缺少 session 处理 |

### 5.5 业务逻辑扫描器（Business Scanner）

检测面向业务的逻辑漏洞：

| 检测项 | 检测方法 | 示例 |
|--------|----------|------|
| 支付金额客户端可控 | 找 `request.POST.get('amount')` 或类似 | 客户端传入价格 |
| 缺少第三方确认 | 支付直接标记为已支付 | `havePay` 自行确认 |
| IDOR | 资源操作只检查存在性未检查所有权 | `music = Music.objects.get(id=music_id)` |
| 批量越权 | 批量操作未校验每个资源的归属 | 批量删除 |
| 速率限制缺失 | 登录/注册接口无限频装饰器 | `login` 无限制 |
| 文件上传无限制 | 未检查文件类型/大小 | `request.FILES` 无校验 |
| 敏感信息日志 | 日志中打印密码/Token | `logger.info(password)` |

---

## 6. 修复引擎

### 6.1 修复生成

Fix 的生成分为两类：

**A. 配置类修复（自动，由规则 fix 定义）**

```python
# 示例：CSRF 修复
fix:
  - type: uncomment
    file: "**/settings.py"
    search: "#.*CsrfViewMiddleware"
    replacement: "    'django.middleware.csrf.CsrfViewMiddleware',"

# 解析 → EditOperation
EditOperation(
    file="crazymusic_backend/settings.py",
    old_string="#    'django.middleware.csrf.CsrfViewMiddleware',",
    new_string="    'django.middleware.csrf.CsrfViewMiddleware',",
    description="取消 CsrfViewMiddleware 注释",
)
```

**B. 代码类修复（需要 Agent 理解上下文）**

对于 SAST 发现的问题，Agent 需要阅读上下文后生成修复代码。例如 SQL 注入修复：

```python
# 原代码
Music.objects.raw(f"SELECT * FROM music WHERE id = {music_id}")

# 修复后
Music.objects.raw("SELECT * FROM music WHERE id = %s", [music_id])
```

这类修复由 Agent 在 Phase 4 生成，不是预先定义的。

### 6.2 修复交互流程

```
用户输入: /security-review
         ↓
扫描完成, 输出摘要 + 发现列表
         ↓
Agent: "🛠 是否应用以下修复? (输入编号或 all)"
         ↓
用户: "1,3,5"
         ↓
Agent 对每个编号:
  1. 读取对应 Finding
  2. 读取 Fix.edit_operations
  3. 对每个 EditOperation:
     - 显示 diff
     - 调用 Edit 工具
     - 确认成功
         ↓
Agent: "已应用 3/3 项修复"
```

### 6.3 Edit 操作的安全约束

```
⚠️ 安全规则：
1. 每次 Edit 前，Read 文件确认当前内容
2. 如果文件内容与 old_string 不匹配 → 跳过并报告
3. 如果修改的是 .env 或密钥相关文件 → 额外确认
4. 不修改 node_modules/、venv/、.git/ 中的文件
5. 所有修改记录到操作日志
```

---

## 7. 报告与输出

### 7.1 终端输出（Markdown 格式）

报告分三部分输出：

**第一部分：摘要面板**

```markdown
╔═══════════════════════════════════════════════════════╗
║              🔒 Security Review Report                ║
╠═══════════════════════════════════════════════════════╣
║  Project:        crazymusic-backend                   ║
║  Tech Stack:     Python + Django + SQLite             ║
║  Scan Depth:     Full (5/5 dimensions)                ║
║  Duration:       12.3s                                ║
╚═══════════════════════════════════════════════════════╝

## 摘要

| 严重度 | 数量 | 可自动修复 |
|--------|------|-----------|
| 🔴 Critical | 3 | 3 |
| 🟠 High     | 5 | 4 |
| 🟡 Medium   | 4 | 1 |
| 🟢 Low      | 2 | 0 |
| **合计**    | **14** | **8** |

| 扫描维度 | 🔴 | 🟠🟡🟢 | 合计 |
|----------|----|--------|------|
| Dependency | 1 | 2 | 3 |
| Config     | 2 | 3 | 5 |
| SAST       | 0 | 1 | 1 |
| Auth       | 0 | 2 | 2 |
| Business   | 0 | 3 | 3 |
```

**第二部分：详细发现列表**

```markdown
### 🔴 CRITICAL: CSRF 防护缺失

**文件**: [crazymusic_backend/settings.py:33](crazymusic_backend/settings.py#L33)
**维度**: Config | **CWE**: CWE-352 | **OWASP**: A01:2021

**风险**: CSRF 中间件被注释，所有 POST 请求无 CSRF 保护。

**攻击场景**: 攻击者构造恶意页面，诱导已登录用户提交表单，
              可执行任意操作（如修改密码、创建订单等）。

**代码**:
```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    ...
    # 'django.middleware.csrf.CsrfViewMiddleware',  ← 被注释
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]
```

**修复**:
```python
# 取消注释第 33 行
'csrf.CsrfViewMiddleware',
```

**修复工作量**: 5 分钟 | **自动修复**: ✅
```

**第三部分：交互选项**

```
## 🛠 应用修复

输入编号应用，或用范围命令：

  [1]  🔴 CSRF 防护缺失
  [2]  🔴 SECRET_KEY 硬编码
  [3]  🟠 DEBUG=True
  [4]  🟠 ALLOWED_HOSTS=['*']
  [5]  🟠 CORS_ALLOW_ALL_ORIGINS=True
  [c]  配置类修复 (5 项)
  [a]  全部 (8 项)
  [q]  退出

请输入 > _
```

### 7.2 JSON 输出格式

当 `--output json` 时输出结构化 JSON：

```json
{
  "metadata": {
    "project_name": "crazymusic-backend",
    "tech_stack": {
      "languages": ["python"],
      "frameworks": ["django"],
      "dep_managers": ["pip"]
    },
    "scan_time_seconds": 12.3,
    "dimensions_covered": ["dependency", "config", "sast", "auth", "business"],
    "generated_at": "2026-07-27T10:30:00Z"
  },
  "summary": {
    "total": 14,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 2,
    "auto_fixable": 8
  },
  "findings": [
    {
      "id": "django-csrf-disabled",
      "dimension": "config",
      "severity": "critical",
      "title": "CSRF 防护缺失",
      "description": "CSRF 中间件被注释...",
      "cwe": "CWE-352",
      "owasp": "A01:2021",
      "file_path": "crazymusic_backend/settings.py",
      "line": 33,
      "attack_scenario": "攻击者构造恶意页面...",
      "auto_fixable": true,
      "fixes": [
        {
          "description": "取消注释 CsrfViewMiddleware",
          "type": "edit",
          "effort": "low",
          "edit_operations": [
            {
              "file": "crazymusic_backend/settings.py",
              "old_string": "#    'django.middleware.csrf.CsrfViewMiddleware',",
              "new_string": "    'django.middleware.csrf.CsrfViewMiddleware',",
              "description": "取消 CsrfViewMiddleware 注释"
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 8. CLI 与交互设计

### 8.1 技能入口点

```markdown
# .claude/skills/security-review.md

---
name: security-review
description: 安全审查 Agent — 扫描项目依赖/配置/代码/认证/业务逻辑安全漏洞并自动修复
---

# Security Review Agent

## 调用方式
用户输入 `/security-review [options]` 时触发。

## 参数解析
- `--quick` → 仅执行 Config + Dependency 扫描
- `--focus <dimension>` → 仅执行指定维度扫描
- `--apply <ids|all>` → 扫描后自动应用修复
- `--no-fix` → 仅报告不修复
- `--output <terminal|json>` → 输出格式
- `--diff <ref>` → 仅扫描与 ref 的代码差异

## 执行流程
1. Phase 1: 项目探针 — 识别技术栈
2. Phase 2: 并行扫描 — 根据参数选择扫描维度
3. Phase 3: 聚合去重
4. Phase 4: 生成修复
5. Phase 5: 输出报告 + 交互式修复
```

### 8.2 子 Agent 定义模板

```markdown
# .claude/agents/config-scanner.md

---
name: config-scanner
description: 配置安全扫描 Agent - 检查框架配置中的安全缺陷
model: sonnet
tools: Read, Glob, Grep
---

# Config Scanner

## 任务
扫描项目的配置文件（settings.py、application.yml 等）中的安全配置问题。

## 规则目录
参考 `rules/` 下的 YAML 规则文件，根据项目探针结果加载。

## 输出格式
必须输出 JSON 格式的 Finding 列表，每项包含：
- id, dimension, severity, title, description
- file_path, line
- code_snippet（问题代码片段）
- attack_scenario（攻击场景）
- fixes（修复方案）

## 重要
- 读取规则 YAML 文件来指导扫描
- 每个发现必须有对应的修复方案
- 严重度必须准确
```

### 8.3 交互式修复实现

交互式修复不依赖外部 UI 库，通过 Claude Code 的文本交互实现：

```
伪代码流程：
1. 输出修复菜单（编号 + 严重度 + 标题）
2. 等待用户输入
3. 解析输入：
   - 数字或数字列表 (1,3,5) → 应用指定修复
   - "a" / "all" → 应用全部
   - "c" / "config" → 仅配置类
   - "s" / "sast" → 仅 SAST 类
   - "q" / "quit" → 退出
4. 对每个要应用的 Fix：
   a. 读取文件确认内容
   b. 执行 Edit 操作
   c. 输出结果（成功/失败）
5. 报告汇总
```

---

## 9. 异常处理与边界情况

### 9.1 工具不可用降级

```
场景                   │ 正常模式             │ 降级模式
──────────────────────┼──────────────────────┼──────────────────────
pip-audit 未安装      │ pip-audit --json     │ dependency_db.py
npm audit 未安装      │ npm audit --json     │ 跳过 npm 扫描
bandit 未安装         │ bandit -r . -f json  │ sast_patterns.py
semgrep 未安装        │ semgrep --config auto │ sast_patterns.py
无 Python 运行时      │ N/A                  │ 跳过依赖+SAST扫描
无 Git 仓库           │ --diff 无效          │ 全量扫描
空项目                │ 无发现               │ 报告 "未发现安全问题"
```

### 9.2 边界情况处理

| 情况 | 处理策略 |
|------|----------|
| 项目文件过多 (> 10000) | 限制扫描文件数，抽样扫描 |
| 文件过大 (> 1MB) | 只读取前 1000 行 |
| 二进制文件 | 跳过（仅扫描文本文件） |
| node_modules/ / venv/ | 默认排除 |
| 不可读文件（权限不足） | 跳过并记录警告 |
| YAML 规则语法错误 | 跳过该规则，记录错误，继续加载其他规则 |
| 规则返回大量误报 | 通过多 Agent 交叉验证减少 |
| 编码问题（非 UTF-8） | 尝试常见编码（GBK、Latin-1） |
| 网络请求超时（pip-audit） | 超时重试 1 次，失败→降级模式 |

### 9.3 安全约束

```
1. Agent 不自动写入 .env 或密钥文件（需要用户确认）
2. Agent 不修改未在报告中列出的文件
3. 每次 Edit 前验证 old_string 与文件内容一致
4. 不在非文本文件上执行 Edit
5. 不修改 git 钩子或 CI/CD 触发文件
6. 敏感发现（密钥泄露）仅报告，不自动修复
```

---

## 10. 测试策略

### 10.1 测试项目

使用 `e:\crazymusic-front\crazymusic-backend\` 作为测试目标。该项目的已知安全问题如下：

| ID | 类型 | 严重度 | 预期结果 |
|----|------|--------|----------|
| T1 | CSRF 中间件缺失 | CRITICAL | `Config` → 发现 `CsrfViewMiddleware` 被注释 |
| T2 | SECRET_KEY 硬编码 | CRITICAL | `Config` → 发现密钥在源码中 |
| T3 | DEBUG=True | HIGH | `Config` → 发现 DEBUG 开启 |
| T4 | ALLOWED_HOSTS=['*'] | HIGH | `Config` → 发现通配符 Host |
| T5 | CORS_ALLOW_ALL_ORIGINS | HIGH | `Config` → 发现全开 CORS |
| T6 | 管理员接口无角色校验 | MEDIUM | `Auth` → 发现 `loadUser` 等无角色检查 |
| T7 | 密码策略过弱 | MEDIUM | `Auth` → 发现仅校验长度 |
| T8 | 无登录限频 | MEDIUM | `Business` → 发现登录接口不限频 |
| T9 | Token 明文传输 | MEDIUM | `Auth` → 发现 session_key 作 token |

### 10.2 测试维度

| 测试类型 | 覆盖范围 | 验证方式 |
|----------|----------|----------|
| 功能测试 | 每个扫描维度至少发现 1 个真实漏洞 | 对测试项目运行 Agent |
| 降级测试 | 移除所有外部工具后扫描 | 输出应与正常模式一致 |
| 性能测试 | 扫描时间 < 30s | 计时 |
| 边界测试 | 空项目、大项目、二进制项目 | 不崩溃 |
| 修复测试 | 自动修复后验证文件内容变化 | diff 对比 |

### 10.3 测试执行

```bash
# 全量扫描
/security-review

# 快速扫描
/security-review --quick

# JSON 输出（CI 集成验证）
/security-review --output json

# 增量扫描（如果 git 可用）
/security-review --diff HEAD

# 焦点扫描
/security-review --focus config
/security-review --focus sast
```

---

## 11. 开发序列

### 11.1 里程碑总览

```
Week 1           Week 2           Week 3
┌────────┐      ┌────────┐      ┌────────┐
│  M1+M2 │─────→│  M3+M4 │─────→│  M5+M6 │
│ 核心   │      │ SAST   │      │ 业务   │
│ 框架   │      │ 依赖   │      │ 逻辑   │
│ 配置   │      │ 扫描   │      │ CI/CD  │
└────────┘      └────────┘      └────────┘
```

### 11.2 M1: 核心框架（Day 1-2）

| 任务 | 文件 | 说明 |
|------|------|------|
| 1.1 | `.claude/skills/security-review.md` | 创建技能定义，解析 CLI 参数，编排 5 Phase |
| 1.2 | `.claude/agents/config-scanner.md` | 配置扫描 Agent（作为首个可运行的 Agent） |
| 1.3 | `models.py` | 定义 Finding、Fix、EditOperation、Report、Severity |
| 1.4 | `rules/base/secrets-in-code.yml` | 基础规则：硬编码密钥 |
| 1.5 | `rules/base/debug-mode.yml` | 基础规则：Debug 模式 |
| 1.6 | `rules/django/csrf.yml` | Django 规则：CSRF |
| 1.7 | `rules/django/debug-true.yml` | Django 规则：DEBUG |
| 1.8 | `rules/django/allowed-hosts.yml` | Django 规则：ALLOWED_HOSTS |
| 1.9 | `rules/django/cors.yml` | Django 规则：CORS |
| 1.10 | `rules/django/secret-key.yml` | Django 规则：SECRET_KEY |
| 1.11 | 报告输出 | 终端 Markdown 摘要 + 详细列表 |
| 1.12 | Phase 3 聚合去重 | 合并、排序、去重算法 |

**验证条件**：对 crazymusic-backend 运行 `/security-review --focus config` 应发现至少 5 个配置漏洞。

### 11.3 M2: 配置扫描完善（Day 2-3）

| 任务 | 文件 | 说明 |
|------|------|------|
| 2.1 | `rules/django/session-cookie.yml` | Session Cookie 安全 |
| 2.2 | `rules/django/database.yml` | SQLite 生产告警 |
| 2.3 | `rules/django/auth-config.yml` | AllowAny 默认权限 |
| 2.4 | `rules/python/sql-injection.yml` | SQL 注入（配置类） |
| 2.5 | `rules/docker/root-user.yml` | Docker root 用户 |
| 2.6 | `rules/cicd/secrets-in-ci.yml` | CI/CD 密钥泄露 |
| 2.7 | 交互式修复 | 用户选择 → 自动 Edit |

**验证条件**：可交互式修复 CSRF、DEBUG、ALLOWED_HOSTS。

### 11.4 M3: 依赖扫描（Day 3-4）

| 任务 | 文件 | 说明 |
|------|------|------|
| 3.1 | `.claude/agents/dependency-scanner.md` | 依赖扫描 Agent |
| 3.2 | `dependency_db.py` | 内置 CVE 对照表 |
| 3.3 | 工具集成（pip-audit） | 异步调用 + 解析 JSON |
| 3.4 | 工具集成（npm audit） | 同上 |
| 3.5 | 降级模式 | 无工具时使用内置 CVE 表 |

**验证条件**：扫描 crazymusic-backend 的 requirements.txt。

### 11.5 M4: SAST 扫描（Day 4-5）

| 任务 | 文件 | 说明 |
|------|------|------|
| 4.1 | `.claude/agents/sast-scanner.md` | SAST 扫描 Agent |
| 4.2 | `sast_patterns.py` | 内置模式库（SQL/XSS/命令注入/路径遍历/SSRF） |
| 4.3 | bandit 集成 | 调用 + 输出解析 |
| 4.4 | 降级验证 | 模式匹配 vs bandit 结果对比 |
| 4.5 | `rules/python/` 补充规则 | 对应 sast_patterns 的 YAML 规则 |

**验证条件**：在测试项目中发现 XSS 或 SQL 注入风险。

### 11.6 M5: 认证授权 + 业务逻辑（Day 5-7）

| 任务 | 文件 | 说明 |
|------|------|------|
| 5.1 | `.claude/agents/auth-scanner.md` | 认证授权 Agent |
| 5.2 | `.claude/agents/business-scanner.md` | 业务逻辑 Agent |
| 5.3 | Auth 规则（YAML） | 角色校验、CSRF、Token 传输 |
| 5.4 | Business 规则（YAML） | 支付、IDOR、限频、文件上传 |
| 5.5 | 交叉验证 | 多 Agent 确认减少误报 |

**验证条件**：发现管理员接口未校验角色、密码策略过弱。

### 11.7 M6: CI/CD 集成（Day 7）

| 任务 | 文件 | 说明 |
|------|------|------|
| 6.1 | JSON 输出定型 | 完整 JSON Schema |
| 6.2 | `--diff` 增量扫描 | git diff → 仅扫描变更文件 |
| 6.3 | GitHub Action 示例 | `.github/workflows/security-review.yml` |
| 6.4 | 文档 | README.md 完善 |

---

## 附录 A：参考资源

| 资源 | 位置 |
|------|------|
| 安全审查 Agent 模板（官方） | `C:\Users\Admin\.claude\plugins\marketplaces\claude-plugins-official\plugins\code-modernization\agents\security-auditor.md` |
| 子 Agent 模板指南 | `C:\Users\Admin\.claude\plugins\marketplaces\claude-plugins-official\plugins\claude-code-setup\skills\claude-automation-recommender\references\subagent-templates.md` |
| 全局安全插件 | `C:\Users\Admin\.claude\plugins\marketplaces\claude-plugins-official\plugins\security-guidance\` |
| Django 安全清单 | https://docs.djangoproject.com/en/stable/topics/security/ |
| OWASP Top 10 (2021) | https://owasp.org/www-project-top-ten/ |
| pip-audit | https://github.com/pypa/pip-audit |
| bandit | https://github.com/PyCQA/bandit |

## 附录 B：文件变更清单

| 文件 | 动作 | 所属里程碑 |
|------|------|-----------|
| `d:\pythonProject5\agent\security-review\.claude\skills\security-review.md` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\.claude\agents\config-scanner.md` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\.claude\agents\dependency-scanner.md` | 新建 | M3 |
| `d:\pythonProject5\agent\security-review\.claude\agents\sast-scanner.md` | 新建 | M4 |
| `d:\pythonProject5\agent\security-review\.claude\agents\auth-scanner.md` | 新建 | M5 |
| `d:\pythonProject5\agent\security-review\.claude\agents\business-scanner.md` | 新建 | M5 |
| `d:\pythonProject5\agent\security-review\models.py` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\utils.py` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\sast_patterns.py` | 新建 | M4 |
| `d:\pythonProject5\agent\security-review\dependency_db.py` | 新建 | M3 |
| `d:\pythonProject5\agent\security-review\rules\base\secrets-in-code.yml` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\rules\base\debug-mode.yml` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\rules\base\weak-crypto.yml` | 新建 | M2 |
| `d:\pythonProject5\agent\security-review\rules\django\csrf.yml` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\rules\django\debug-true.yml` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\rules\django\allowed-hosts.yml` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\rules\django\cors.yml` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\rules\django\secret-key.yml` | 新建 | M1 |
| `d:\pythonProject5\agent\security-review\rules\django\session-cookie.yml` | 新建 | M2 |
| `d:\pythonProject5\agent\security-review\rules\django\database.yml` | 新建 | M2 |
| `d:\pythonProject5\agent\security-review\rules\django\auth-config.yml` | 新建 | M2 |
| `d:\pythonProject5\agent\security-review\rules\python\sql-injection.yml` | 新建 | M2 |
| `d:\pythonProject5\agent\security-review\rules\docker\root-user.yml` | 新建 | M2 |
| `d:\pythonProject5\agent\security-review\rules\cicd\secrets-in-ci.yml` | 新建 | M2 |
| `d:\pythonProject5\agent\security-review\README.md` | 新建 | M6 |
