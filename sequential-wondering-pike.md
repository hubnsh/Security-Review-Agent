# Security Review Agent — 详细设计说明书

> **版本**: v1.0  
> **日期**: 2026-07-27  
> **基于**: security-review-requirements.md v2.0 + 工作区探索结果

---

## 目录

- [1. 系统架构](#1-系统架构)
- [2. 模块详细设计](#2-模块详细设计)
- [3. 规则引擎设计](#3-规则引擎设计)
- [4. 项目探针设计](#4-项目探针设计)
- [5. 扫描器设计](#5-扫描器设计)
- [6. 修复引擎设计](#6-修复引擎设计)
- [7. 报告输出设计](#7-报告输出设计)
- [8. CI/CD 集成设计](#8-cicd-集成设计)
- [9. 文件清单与实现顺序](#9-文件清单与实现顺序)
- [10. 验证方案](#10-验证方案)

---

## 1. 系统架构

### 1.1 三层架构

```
┌─────────────────────────────────────────────────────────────┐
│                    用户接口层 (User Interface)               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Claude Code 技能 (SKILL.md)                         │   │
│  │  /security-review [--quick|--focus|--apply|...]      │   │
│  └─────────────────────┬────────────────────────────────┘   │
└────────────────────────┼────────────────────────────────────┘
                         │
┌────────────────────────┼────────────────────────────────────┐
│                    编排层 (Orchestration)                   │
│  ┌─────────────────────┴────────────────────────────────┐   │
│  │  engine.py — 扫描引擎主入口                          │   │
│  │  Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5    │   │
│  └─────────────────────┬────────────────────────────────┘   │
└────────────────────────┼────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                    核心逻辑层 (Core Logic)                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ 探针引擎  │ │ 规则引擎  │ │ 扫描器集  │ │ 修复引擎  │      │
│  │ probe.py │ │ rule_eng │ │ scanners/│ │ fixers/  │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 数据流

```
User Input → SKILL.md (技能加载) → engine.py (编排)
  → Phase 1: project_probe.py → 返回 ProjectInfo
  → Phase 2: scanners/*.py (并行) → 返回 List[Finding]
  → Phase 3: engine.py (聚合去重) → 返回 List[Finding]
  → Phase 4: fixers/*.py → 为每个 Finding 生成 Fix
  → Phase 5: reporters/*.py → 输出 Report
```

### 1.3 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| **编排方式** | Workflow 多 Agent 并行 | 5 个扫描维度互不依赖，并行可大幅降低总耗时 |
| **核心语言** | Python | 跨平台、便于集成 pip-audit/bandit/semgrep |
| **规则格式** | YAML | 人类可读写、Claude 易生成、热加载 |
| **外部依赖** | 可选，自动降级 | pip-audit/bandit/semgrep 非必需，缺失时用内置规则 |
| **修复方式** | 生成 Edit 操作 + 用户确认 | 不擅自修改代码，用户逐条确认 |
| **CLI 入口** | Claude Code Skill + Python CLI | 双重入口：Claude 中 `/security-review`，终端中 `python engine.py` |
| **CVE 检查** | pip-audit CLI 封装 | pip-audit 查询 PyPI/OSV API，无需本地 CVE 数据库 |

---

## 2. 模块详细设计

### 2.1 `models.py` — 数据模型

```python
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

# ── 枚举 ──────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def level(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    @property
    def emoji(self) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}[self.value]

class ScanDimension(Enum):
    DEPENDENCY = "dependency"
    CONFIG = "config"
    SAST = "sast"
    AUTH = "auth"
    BUSINESS = "business"

class FixType(Enum):
    ENV_VAR = "env_var"         # 移到环境变量
    EDIT = "edit"               # 代码编辑
    CONFIG = "config"           # 配置修改
    ARCHITECTURAL = "arch"      # 架构级重构（仅建议）

class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    JAVA = "java"
    RUBY = "ruby"
    RUST = "rust"
    PHP = "php"
    CSHARP = "csharp"
    CPP = "cpp"
    SWIFT = "swift"
    KOTLIN = "kotlin"

# ── 核心数据类 ────────────────────────────────────────

@dataclass
class ProjectInfo:
    """Phase 1 输出：项目探测结果"""
    root_path: str
    languages: list[Language] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    dependency_files: dict[str, str] = field(default_factory=dict)  # type → path
    has_docker: bool = False
    has_k8s: bool = False
    has_ci: bool = False
    git_available: bool = False
    has_frontend: bool = False

@dataclass
class EditOperation:
    """一个原子编辑操作"""
    file: str
    old_string: str
    new_string: str
    description: str = ""

@dataclass
class Fix:
    """一个修复方案"""
    description: str
    fix_type: FixType
    edit_operations: list[EditOperation] = field(default_factory=list)
    effort: str = "medium"  # 5min / 30min / 2h / 1d

@dataclass
class Finding:
    """一个安全发现"""
    id: str
    dimension: ScanDimension
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    attack_scenario: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fixes: list[Fix] = field(default_factory=list)

@dataclass
class Report:
    """完整扫描报告"""
    project_name: str
    tech_stack: dict
    scan_time_seconds: float
    dimensions_covered: list[str]
    findings: list[Finding]

    @property
    def total(self) -> int: return len(self.findings)

    @property
    def by_severity(self) -> dict:
        counts = {}
        for s in Severity:
            counts[s.value] = sum(1 for f in self.findings if f.severity == s)
        return counts

    @property
    def auto_fixable(self) -> int:
        return sum(1 for f in self.findings if any(
            fix.fix_type in (FixType.EDIT, FixType.CONFIG) for fix in f.fixes
        ))
```

### 2.2 `scanners/project_probe.py` — 项目探针

```python
class ProjectProbe:
    """
    项目探针：自动检测项目技术栈。
    
    工作流程:
    1. 遍历项目根目录，收集文件分布统计
    2. 根据特征文件确定语言 (heuristic scoring)
    3. 根据 package.json / settings.py 等确定框架
    4. 识别依赖管理工具和配置文件
    5. 返回 ProjectInfo
    """

    # 语言检测权重表
    LANGUAGE_INDICATORS = {
        Language.PYTHON: {
            "extensions": {".py": 10, ".pyx": 5},
            "files": {"requirements.txt": 20, "pyproject.toml": 20, 
                      "setup.py": 15, "Pipfile": 15, "MANIFEST.in": 5},
        },
        Language.JAVASCRIPT: {
            "extensions": {".js": 8, ".jsx": 5},
            "files": {"package.json": 20},
        },
        Language.TYPESCRIPT: {
            "extensions": {".ts": 8, ".tsx": 5},
            "files": {"tsconfig.json": 15},
        },
        Language.GO: {
            "extensions": {".go": 10},
            "files": {"go.mod": 20, "go.sum": 5},
        },
        Language.JAVA: {
            "extensions": {".java": 10},
            "files": {"pom.xml": 20, "build.gradle": 20, "build.gradle.kts": 15},
        },
        Language.RUBY: {
            "extensions": {".rb": 8},
            "files": {"Gemfile": 20, "Gemfile.lock": 10},
        },
        Language.RUST: {
            "extensions": {".rs": 10},
            "files": {"Cargo.toml": 20},
        },
        Language.PHP: {
            "extensions": {".php": 8},
            "files": {"composer.json": 20},
        },
        Language.CSHARP: {
            "extensions": {".cs": 8},
            "files": {"*.csproj": 15, "*.sln": 10},
        },
        Language.CPP: {
            "extensions": {".cpp": 6, ".c": 6, ".h": 3, ".hpp": 3},
        },
        Language.SWIFT: {
            "extensions": {".swift": 10},
            "files": {"Package.swift": 15},
        },
        Language.KOTLIN: {
            "extensions": {".kt": 8, ".kts": 5},
        },
    }

    # 框架检测
    FRAMEWORK_DETECTORS = {
        "django":     {"file": "**/settings.py", "content": "django"},
        "flask":      {"file": "**/app.py", "content": "Flask"},
        "fastapi":    {"file": "**/*.py", "content": "FastAPI"},
        "express":    {"file": "**/package.json", "content": "express"},
        "nestjs":     {"file": "**/package.json", "content": "@nestjs/core"},
        "spring":     {"file": "**/pom.xml", "content": "spring-boot"},
        "rails":      {"file": "**/Gemfile", "content": "rails"},
        "laravel":    {"file": "**/composer.json", "content": "laravel"},
        "aspnet":     {"file": "**/*.csproj", "content": "Microsoft.AspNetCore"},
    }

    # 依赖文件检测
    DEPENDENCY_DETECTORS = {
        "pip":      {"files": ["requirements.txt", "pyproject.toml", "Pipfile"]},
        "npm":      {"files": ["package.json", "package-lock.json", "yarn.lock"]},
        "go":       {"files": ["go.mod"]},
        "maven":    {"files": ["pom.xml"]},
        "gradle":   {"files": ["build.gradle"]},
        "bundler":  {"files": ["Gemfile"]},
        "cargo":    {"files": ["Cargo.toml"]},
        "composer": {"files": ["composer.json"]},
    }

    def probe(self, root_path: str) -> ProjectInfo:
        """执行项目探测"""
        ...

    def _score_languages(self, files: list[str]) -> list[tuple[Language, int]]:
        """基于文件分布给语言打分"""
        ...

    def _detect_frameworks(self, files: list[str]) -> list[str]:
        """读取特征文件内容检测框架"""
        ...

    def _detect_dependency_files(self, files: list[str]) -> dict[str, str]:
        """识别依赖文件"""
        ...
```

**探测示例输出**:

```json
{
  "root_path": "e:\\crazymusic-front\\crazymusic-backend",
  "languages": ["python"],
  "frameworks": ["django"],
  "dependency_files": {"pip": "requirements.txt"},
  "has_docker": false,
  "has_k8s": false,
  "has_ci": false,
  "git_available": false,
  "has_frontend": false
}
```

### 2.3 `rule_engine.py` — 规则引擎

```python
class Rule:
    """单条安全规则"""
    id: str
    name: str
    description: str
    severity: Severity
    cwe: Optional[str]
    owasp: Optional[str]
    languages: list[Language]
    frameworks: list[str]
    detect: list[dict]       # 检测条件列表
    fix: Optional[list[dict]]  # 修复方案

class RuleEngine:
    """
    规则引擎：加载 YAML 规则 → 根据项目信息筛选 → 匹配文件 → 生成 Finding。

    支持 5 种检测类型:
    - file_contains: 文件包含某模式
    - file_not_contains: 文件不包含某模式
    - regex: 正则匹配文件内容
    - comment_or_missing: 某行被注释或缺失
    - config_value: 配置项等于某值
    """

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rules: list[Rule] = []

    def load_rules(self) -> int:
        """加载所有 YAML 规则文件，返回数量"""
        ...

    def filter_rules(self, project_info: ProjectInfo) -> list[Rule]:
        """根据项目信息筛选适用规则"""
        ...

    def apply_rules(self, rules: list[Rule], root_path: str) -> list[Finding]:
        """在项目中应用规则，返回发现列表"""
        ...

    def _match_file_contains(self, rule_part: dict, root_path: str) -> list[Finding]:
        """匹配 file_contains 类型"""
        ...

    def _match_regex(self, rule_part: dict, root_path: str) -> list[Finding]:
        """匹配 regex 类型"""
        ...

    def _load_yaml_rule(self, filepath: str) -> Optional[Rule]:
        """加载单条 YAML 规则"""
        ...
```

### 2.4 规则 YAML 格式规范

```yaml
# rules/django/csrf.yml
id: django-csrf-disabled
name: CSRF 中间件缺失
description: 检测 Django 的 CSRF 中间件是否被注释或移除
severity: critical
cwe: CWE-352
owasp: A01:2021
languages: [python]
frameworks: [django]

detect:
  # 条件 1: settings.py 中存在 MIDDLEWARE 列表但缺少 CsrfViewMiddleware
  - type: file_contains
    path: "**/settings.py"
    pattern: "MIDDLEWARE"
  - type: file_not_contains
    path: "**/settings.py"
    pattern: "CsrfViewMiddleware"
  # OR 条件：被注释的 CSRF 中间件
  - type: regex
    path: "**/settings.py"
    pattern: "#.*CsrfViewMiddleware"
    # 只要匹配到任意一个 detect 块就算命中

fix:
  - type: uncomment_or_insert
    file: "**/settings.py"
    search: "#.*CsrfViewMiddleware"
    replacement: "    'django.middleware.csrf.CsrfViewMiddleware',"
  - type: insert_after_match
    file: "**/settings.py"
    anchor: "MIDDLEWARE\\s*=\\s*\\["
    text: "    'django.middleware.csrf.CsrfViewMiddleware',"
```

```yaml
# rules/base/hardcoded-secrets.yml
id: hardcoded-secret-key
name: 硬编码密钥/凭据
description: 检测源码中的硬编码密钥、API 密钥、密码
severity: critical
cwe: CWE-798
languages: [python, javascript, go, java, ruby, php, rust, csharp]
frameworks: []

detect:
  - type: regex
    path: "**/*.{py,js,ts,go,java,rb,php,rs,cs,kt}"
    pattern: '(SECRET_[A-Z_]+\s*[=:]\s*["'"'"'][^"'"'"']{8,}["'"'"'])'
    exclude_patterns:
      - "**/node_modules/**"
      - "**/venv/**"
      - "**/.git/**"
      - "**/__pycache__/**"
      - "*.{md,txt,yaml,yml,json}"
    exclude_value_patterns:
      - "^.*SECRET.*=.*os\\.(getenv|environ)"  # 排除已使用环境变量的
      - "^.*SECRET.*=.*process\\.env"
      - "^.*SECRET.*=.*ENV\\["

fix:
  - type: replace_with_env_var
    file: "**/settings.py"
    suggestion: |
      将 SECRET_KEY 移到环境变量:
      1. 在 .env 文件中添加: DJANGO_SECRET_KEY=your-secret-key-here
      2. 在 settings.py 中改为: SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
```

```yaml
# rules/django/debug-true.yml
id: django-debug-true
name: DEBUG 模式开启
description: Django DEBUG 模式在生产环境会泄露敏感信息
severity: high
cwe: CWE-200
languages: [python]
frameworks: [django]

detect:
  - type: config_value
    path: "**/settings.py"
    key: "DEBUG"
    value: "True"

fix:
  - type: replace_line
    file: "**/settings.py"
    pattern: "^DEBUG\\s*=\\s*True"
    replacement: |
      DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'
  - type: replace_line
    alternative: true  # 替代方案
    file: "**/settings.py"
    pattern: "^DEBUG\\s*=\\s*True"
    replacement: "DEBUG = False"
```

---

## 3. 扫描器设计

### 3.1 扫描器基类

```python
class BaseScanner(ABC):
    """所有扫描器的基类"""
    
    @property
    def dimension(self) -> ScanDimension:
        """返回扫描维度"""
        ...
    
    @abstractmethod
    def scan(self, project_info: ProjectInfo, root_path: str) -> list[Finding]:
        """执行扫描，返回发现列表"""
        ...
```

### 3.2 `DependencyScanner` — 依赖漏洞扫描

```python
class DependencyScanner(BaseScanner):
    """
    依赖漏洞扫描。
    
    扫描策略:
    1. 根据 ProjectInfo.dependency_files 确定生态
    2. 尝试安装并调用外部工具 (pip-audit / npm audit)
    3. 如果工具不可用，降级模式：读取依赖列表 + 内置 CVE 缓存
    4. 解析工具输出为标准 Finding 列表
    """
    
    # 内置 CVE 缓存（降级用）
    # 包含已知高危/严重漏洞，定期更新
    BUILTIN_CVE_DB: dict[str, list[dict]] = {
        # 格式: "package_name": [{"id": "CVE-xxx", "severity": "high", ...}]
    }
    
    # pip install 超时时间
    INSTALL_TIMEOUT = 30  # seconds
    
    def scan(self, project_info: ProjectInfo, root_path: str) -> list[Finding]:
        findings = []
        
        if "pip" in project_info.dependency_files:
            findings.extend(self._scan_python(project_info, root_path))
        
        if "npm" in project_info.dependency_files:
            findings.extend(self._scan_npm(project_info, root_path))
        
        # 未来可扩展 go, maven, cargo 等
        return findings
    
    def _scan_python(self, ...) -> list[Finding]:
        """Python 依赖扫描"""
        # 1. 尝试调用 pip-audit
        # 2. 如果 pip-audit 不可用，安装它（由用户确认）
        # 3. 解析 JSON 输出 → 转为 Finding 列表
        ...
    
    def _scan_npm(self, ...) -> list[Finding]:
        """Node.js 依赖扫描"""
        # 1. 检查是否有 lockfile
        # 2. 运行 npm audit --json
        # 3. 解析 JSON 输出 → 转为 Finding 列表
        ...
    
    def _fallback_python(self, ...) -> list[Finding]:
        """降级模式：匹配内置 CVE 库"""
        # 1. 读取 requirements.txt
        # 2. 解析包名和版本
        # 3. 查询 BUILTIN_CVE_DB
        ...
    
    def _parse_pip_audit_json(self, json_str: str) -> list[Finding]:
        """解析 pip-audit JSON 输出"""
        ...
    
    def _parse_npm_audit_json(self, json_str: str) -> list[Finding]:
        """解析 npm audit --json 输出"""
        ...
```

**pip-audit JSON 转 Finding 示例**:

```python
# pip-audit JSON 输入:
{
  "dependencies": [{
    "name": "django",
    "version": "5.2.12",
    "vulns": [{
      "id": "PYSEC-2024-XXX",
      "fix_versions": ["5.2.13"],
      "aliases": ["CVE-2024-XXXXX"],
      "description": "Django contains a potential directory-traversal..."
    }]
  }]
}

# 输出 Finding:
Finding(
    id="dep-pip-django-cve-2024-xxxxx",
    dimension=ScanDimension.DEPENDENCY,
    severity=Severity.HIGH,
    title="Django 5.2.12 存在目录遍历漏洞",
    description="Django 5.2.12 contains a potential directory-traversal...",
    cwe="CWE-22",
    fixes=[Fix(
        description="升级 Django 到 >=5.2.13",
        fix_type=FixType.EDIT,
        edit_operations=[EditOperation(
            file="requirements.txt",
            old_string="Django==5.2.12",
            new_string="Django==5.2.13"
        )]
    )]
)
```

### 3.3 `ConfigScanner` — 配置安全审查

```python
class ConfigScanner(BaseScanner):
    """
    配置安全审查。
    
    扫描策略:
    1. 加载项目探针识别的框架
    2. 加载对应框架的配置规则
    3. 读取关键配置文件 (settings.py, application.yml, .env 等)
    4. 匹配规则 → 生成 Finding
    
    内置 Django 配置检查（无需外部工具）:
    - DEBUG 模式
    - SECRET_KEY 硬编码
    - CSRF 中间件缺失
    - ALLOWED_HOSTS 过于宽松
    - CORS 配置过于宽松
    - Session 安全 Cookie 未配置
    - 文件上传未限制
    - HTTPS 未强制
    - 数据库引擎（SQLite 用于生产警告）
    """
    
    def __init__(self):
        self._builtin_checks: dict[str, list[Callable]] = {
            "django": [self._check_django_debug, self._check_django_secret_key, ...],
            "express": [self._check_express_helmet, self._check_express_cors, ...],
            "spring": [self._check_spring_actuator, ...],
        }
```

### 3.4 `SastScanner` — 静态代码安全分析

```python
class SastScanner(BaseScanner):
    """
    静态代码安全分析。
    
    扫描策略:
    1. 优先使用 semgrep（如已安装）
    2. 其次使用 bandit（如已安装）
    3. 降级使用内置 SAST_PATTERNS 正则匹配
    
    内置 SAST 规则覆盖:
    - SQL 注入 (Python/JS/Go/Java)
    - 命令注入 (Python/JS)
    - 路径遍历 (Python/JS)
    - 不安全反序列化 (Python/Java)
    - SSRF (Python/JS/Java)
    - XSS (JS/TS)
    - 原型污染 (JS/TS)
    - eval 使用 (JS/TS/Python)
    - 硬编码凭据 (全语言)
    - 弱加密算法 (全语言)
    """
    
    # 内置模式库
    PATTERNS: dict[str, dict[str, list[tuple[str, str, Severity, str]]]] = {
        "sql-injection": {
            "python": [
                (r"\.raw\(\s*f[\"']", "Django raw() with f-string", Severity.HIGH, "CWE-89"),
                (r"cursor\.execute\(\s*f[\"']", "cursor.execute() with f-string", Severity.HIGH, "CWE-89"),
            ],
            "javascript": [
                (r"db\.\w+\.\$where\(\s*[\"']\s*\+", "MongoDB $where concatenation", Severity.HIGH, "CWE-89"),
            ],
            "go": [
                (r"\.Raw\(\s*f[\"']", "GORM raw f-string query", Severity.HIGH, "CWE-89"),
            ],
            "java": [
                (r"Statement\.executeQuery\(\s*[\"']\\s*\\+", "Raw Statement usage", Severity.HIGH, "CWE-89"),
            ],
        },
        "command-injection": {
            "python": [
                (r"os\.system\(\s*f[\"']", "os.system() with f-string", Severity.CRITICAL, "CWE-78"),
                (r"subprocess\.[a-zA-Z]+\(\s*f[\"']", "subprocess with f-string", Severity.CRITICAL, "CWE-78"),
            ],
            "javascript": [
                (r"exec\(\s*f[\"']", "exec() with template literal", Severity.CRITICAL, "CWE-78"),
            ],
        },
        "path-traversal": {
            "python": [
                (r"open\(\s*os\.path\.join\([^)]*,\s*(?:request|user|input|filepath|filename)",
                 "Path traversal via os.path.join", Severity.HIGH, "CWE-22"),
            ],
            "javascript": [
                (r"res\.sendFile\(\s*(?:req\.|body\.|query\.)",
                 "Path traversal in sendFile()", Severity.HIGH, "CWE-22"),
            ],
        },
        "unsafe-deserialization": {
            "python": [
                (r"pickle\.loads?\(", "Unsafe pickle deserialization", Severity.CRITICAL, "CWE-502"),
                (r"yaml\.load\(\s*(?!.*Loader)", "Unsafe yaml.load()", Severity.HIGH, "CWE-502"),
            ],
            "java": [
                (r"ObjectInputStream\.readObject\(", "Unsafe deserialization", Severity.CRITICAL, "CWE-502"),
            ],
        },
        "ssrf": {
            "python": [
                (r"requests\.(get|post|put|delete)\(\s*(?:request|user|input)",
                 "SSRF via user input to requests", Severity.HIGH, "CWE-918"),
            ],
            "javascript": [
                (r"fetch\(\s*(?:req\.|body\.|query\.)",
                 "SSRF via user input to fetch()", Severity.HIGH, "CWE-918"),
            ],
        },
        "xss": {
            "javascript": [
                (r"innerHTML\s*=\s*(?:req\.|body\.|query\.|params\.)",
                 "XSS via innerHTML assignment", Severity.HIGH, "CWE-79"),
                (r"dangerouslySetInnerHTML\s*=", "XSS via dangerouslySetInnerHTML", Severity.HIGH, "CWE-79"),
                (r"v-html\s*=", "Vue v-html XSS risk", Severity.MEDIUM, "CWE-79"),
            ],
        },
        "weak-crypto": {
            "python": [
                (r"hashlib\.md5\(", "Weak MD5 hash usage", Severity.MEDIUM, "CWE-327"),
                (r"hashlib\.sha1\(", "Weak SHA-1 hash usage", Severity.MEDIUM, "CWE-327"),
            ],
            "go": [
                (r"crypto/md5", "Weak MD5 imported", Severity.MEDIUM, "CWE-327"),
                (r"crypto/sha1", "Weak SHA-1 imported", Severity.MEDIUM, "CWE-327"),
            ],
        },
    }
```

### 3.5 `BusinessScanner` — 业务逻辑安全审查

```python
class BusinessScanner(BaseScanner):
    """
    业务逻辑安全审查。
    
    主要针对代码结构进行分析，而非简单的模式匹配。
    使用启发式规则检测。
    
    检测项:
    - 认证：登录接口是否有速率限制
    - 授权：管理员接口是否有角色校验
    - 支付：金额是否来自可信源
    - 会话：Token 管理是否安全
    - 数据校验：输入是否经过校验
    """
    
    # 业务逻辑检测规则（Python/Django 示例）
    PATTERNS = {
        "no-rate-limit": {
            "python": [
                (r"def\s+login\s*\(", "Login endpoint without rate limiting — check for throttling"),
                (r"def\s+register\s*\(", "Register endpoint without rate limiting"),
            ],
        },
        "missing-auth": {
            "python": [
                (r"permission_classes\s*=\s*\[.*AllowAny.*\]",
                 "Endpoint with AllowAny permission — verify if intentional"),
            ],
        },
        "idor": {
            "python": [
                (r"\.objects\.get\(\s*id\s*=\s*(?!.*request\.user)",
                 "IDOR risk: object lookup by ID without ownership check"),
            ],
        },
        "hardcoded-password-check": {
            "python": [
                (r"len\(.*new_password.*\)\s*<\s*\d+",
                 "Weak password policy: only length check"),
            ],
        },
    }
```

---

## 4. 修复引擎设计

### 4.1 `fixers/edit_generator.py`

```python
class EditGenerator:
    """
    修复方案生成器。
    
    根据 Finding.fixes 中的 Fix 定义，生成可直接执行的 Edit 操作。
    
    修复类型处理:
    - FixType.EDIT: 直接生成 EditOperation（替换/取消注释/插入）
    - FixType.CONFIG: 生成配置修改 EditOperation
    - FixType.ENV_VAR: 生成环境变量迁移方案（多步操作）
    - FixType.ARCHITECTURAL: 仅生成建议文本，无自动 Edit
    """
    
    @staticmethod
    def generate_edit_from_rule(rule_fix: dict, file_path: str) -> list[EditOperation]:
        """
        根据规则中的 fix 定义生成编辑操作。
        
        fix 类型:
        - uncomment_or_insert: 取消注释或插入行
        - replace_line: 替换匹配行
        - insert_after_match: 在匹配后插入
        - replace_with_env_var: 替换为环境变量
        - add_to_gitignore: 添加到 .gitignore
        """
        fix_type = rule_fix.get("type")
        
        if fix_type == "uncomment_or_insert":
            # 尝试取消注释，如果找不到则插入
            return [EditOperation(
                file=file_path,
                old_string=rule_fix["search"],
                new_string=rule_fix["replacement"],
                description=f"取消注释 {rule_fix['search']}"
            )]
        
        elif fix_type == "replace_line":
            return [EditOperation(
                file=file_path,
                old_string=rule_fix["pattern"],
                new_string=rule_fix["replacement"],
                description=f"替换 {rule_fix['pattern']}"
            )]
        
        # ... 其他类型
```

### 4.2 交互式修复流程

```
用户运行 /security-review
  → 扫描完成，输出报告
  → 显示交互式选项:
    [1] 🔴 恢复 CSRF 中间件
    [2] 🔴 将 SECRET_KEY 移到环境变量
    ...
    [all] 应用全部
    
用户选择 → 确认 → Agent 执行 Edit 操作
  → 用户可查看 Edit 预览
  → 确认后 Claude Code 应用修改
```

---

## 5. 报告输出设计

### 5.1 `reporters/terminal.py`

```python
class TerminalReporter:
    """
    终端报告输出。
    生成彩色 Markdown 格式报告，含 Emoji 严重度标识。
    """
    
    def generate(self, report: Report) -> str:
        """生成完整报告文本"""
        sections = [
            self._generate_header(report),
            self._generate_summary(report),
            self._generate_findings(report),
            self._generate_interactive_prompt(report),
        ]
        return "\n\n".join(sections)
    
    def _generate_header(self, report: Report) -> str:
        return f"""╔{'═' * 55}╗
║              🔒 Security Review Report                ║
╠{'═' * 55}╣
║  Project:    {report.project_name:<45}║
║  Tech Stack: {self._format_tech_stack(report.tech_stack):<45}║
║  Duration:   {report.scan_time_seconds:<10.1f}s{' ' * 34}║
║  Dimensions: {', '.join(report.dimensions_covered):<45}║
╚{'═' * 55}╝"""
    
    def _generate_summary(self, report: Report) -> str:
        by_sev = report.by_severity
        return f"""## 📊 扫描摘要

| 严重度 | 数量 |
|--------|------|
| 🔴 Critical | {by_sev['critical']} |
| 🟠 High     | {by_sev['high']} |
| 🟡 Medium   | {by_sev['medium']} |
| 🟢 Low      | {by_sev['low']} |
| **Total**   | **{report.total}** |

🛠 可自动修复: {report.auto_fixable}/{report.total}"""
    
    def _generate_findings(self, report: Report) -> str:
        """为每个 Finding 生成详细报告"""
        lines = []
        for i, f in enumerate(report.findings, 1):
            lines.append(f"""
### {f.severity.emoji} [{f.severity.value.upper()}] {f.title}

**文件**: `{f.file_path}:{f.line}`  | **维度**: {f.dimension.value}  | **CWE**: {f.cwe or '-'}

**风险**: {f.description}

**攻击场景**: {f.attack_scenario or 'N/A'}"""
            )
            if f.fixes:
                lines.append("\n**修复方案**:")
                for j, fix in enumerate(f.fixes, 1):
                    lines.append(f"\n  {j}. {fix.description} [{fix.effort}]")
                    for op in fix.edit_operations:
                        lines.append(f"     └→ `{op.file}`: {op.description}")
            lines.append("\n---")
        return "\n".join(lines)
```

### 5.2 终端输出示例

```
╔═══════════════════════════════════════════════════════╗
║              🔒 Security Review Report                ║
╠═══════════════════════════════════════════════════════╣
║  Project:    crazymusic-backend                       ║
║  Tech Stack: Python + Django + SQLite                 ║
║  Duration:   12.3s                                    ║
║  Dimensions: config, sast, auth, dependency, business ║
╚═══════════════════════════════════════════════════════╝

## 📊 扫描摘要

| 严重度 | 数量 |
|--------|------|
| 🔴 Critical | 3 |
| 🟠 High     | 5 |
| 🟡 Medium   | 4 |
| 🟢 Low      | 2 |
| **Total**   | **14** |

🛠 可自动修复: 8/14

---

### 🔴 [CRITICAL] CSRF 中间件缺失

**文件**: `crazymusic_backend/settings.py:33`  | **维度**: config  | **CWE**: CWE-352

**风险**: CSRF 中间件被注释，所有 POST 请求无 CSRF 保护。

**攻击场景**: 攻击者构造恶意页面，诱导已登录用户提交表单。

**修复方案**:
  1. 取消注释 CsrfViewMiddleware [5min]
     └→ `crazymusic_backend/settings.py`: 取消注释 CsrfViewMiddleware

🛠 是否应用以上修复? (输入编号)
  [1] 🔴 恢复 CSRF 中间件
  [2] 🔴 将 SECRET_KEY 移到环境变量
  ...
  [all] 全部修复  [q] 退出
```

### 5.3 `reporters/json.py`

```python
class JsonReporter:
    """
    JSON 报告输出，用于 CI/CD 集成。
    
    输出 JSON Schema:
    {
      "meta": { "project": "...", "time": 12.3, "dimensions": [...] },
      "summary": { "total": 14, "critical": 3, "high": 5, ... },
      "findings": [
        {
          "id": "config-django-csrf",
          "severity": "critical",
          "title": "CSRF 中间件缺失",
          "file": "settings.py",
          "line": 33,
          "cwe": "CWE-352",
          "description": "...",
          "attack_scenario": "...",
          "fixes": [{ "description": "...", "effort": "5min" }]
        }
      ]
    }
    """
```

---

## 6. 技能定义 (SKILL.md)

```markdown
---
name: security-review
description: 对当前工作区进行多维安全扫描，发现漏洞并提供修复代码
tools: Read, Glob, Grep, Bash, Edit, Write
user-invocable: true
---

# Security Review Agent

## 功能
对当前 Claude Code 工作区进行全自动安全审查，覆盖:
- 依赖漏洞 (CVE)
- 配置安全
- 静态代码安全 (SAST)
- 认证授权
- 业务逻辑安全

## 用法
```
/security-review                    # 全量扫描
/security-review --quick            # 快速扫描
/security-review --focus config     # 仅配置扫描
/security-review --apply all        # 扫描并自动修复
```

## 工作流程
1. 执行项目探针，自动识别技术栈
2. 并行运行 5 个扫描维度
3. 聚合去重，按严重度排序
4. 生成修复方案
5. 输出报告并提供交互式修复

## 规则
规则文件位于 `rules/` 目录，YAML 格式。
```

---

## 7. CI/CD 集成设计

### 7.1 GitHub Action

```yaml
# .github/workflows/security-review.yml
name: Security Review
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install security-review
        run: |
          pip install pip-audit  # for dependency scanning
      - name: Run security scan
        run: |
          python engine.py --output json --no-fix > security-report.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

### 7.2 增量扫描 (`--diff`)

```python
class GitDiffScanner:
    """
    增量扫描：仅扫描与指定 ref 的差异代码。
    
    用法: python engine.py --diff HEAD~1
          python engine.py --diff main
    
    实现:
    1. git diff <ref> --name-only → 获取变更文件列表
    2. 只扫描这些文件
    3. 对于配置扫描，如果 settings.py 没有变更，跳过
    4. 对于依赖扫描，如果 requirements.txt 没有变更，跳过
    """
    
    def get_changed_files(self, ref: str, root_path: str) -> list[str]:
        """获取与 ref 相比的变更文件列表"""
        import subprocess
        result = subprocess.run(
            ["git", "diff", ref, "--name-only"],
            capture_output=True, text=True, cwd=root_path
        )
        if result.returncode != 0:
            return []
        return [os.path.join(root_path, f) for f in result.stdout.strip().split('\n') if f]
```

---

## 8. 文件清单与实现顺序

### 8.1 完整文件清单

```
d:\pythonProject5\agent\security-review\
├── .claude/
│   └── skills/
│       └── security-review.md          # [M1] 技能定义（14 行）
├── rules/
│   ├── base/
│   │   ├── hardcoded-secrets.yml       # [M2] 硬编码密钥
│   │   ├── weak-crypto.yml             # [M2] 弱加密
│   │   └── debug-mode.yml              # [M2] Debug 模式
│   ├── python/
│   │   ├── sql-injection.yml           # [M4] SQL 注入
│   │   ├── command-injection.yml       # [M4] 命令注入
│   │   ├── unsafe-deserialization.yml  # [M4] 反序列化
│   │   └── path-traversal.yml          # [M4] 路径遍历
│   ├── django/
│   │   ├── csrf.yml                    # [M1] CSRF 中间件
│   │   ├── debug-true.yml              # [M1] DEBUG 模式
│   │   ├── allowed-hosts.yml           # [M1] ALLOWED_HOSTS
│   │   ├── cors.yml                    # [M2] CORS 配置
│   │   └── secret-key.yml              # [M2] SECRET_KEY
│   ├── javascript/
│   │   ├── xss.yml                     # [M4] XSS
│   │   └── eval-usage.yml              # [M4] eval
│   ├── docker/
│   │   └── security.yml                # [M2] Docker 安全
│   └── cicd/
│       └── secrets-in-ci.yml           # [M7] CI 密钥泄露
├── scanners/
│   ├── __init__.py
│   ├── base.py                         # [M1] 扫描器基类
│   ├── project_probe.py                # [M1] 项目探针
│   ├── dependency_scanner.py           # [M3] 依赖扫描
│   ├── config_scanner.py               # [M1] 配置扫描
│   ├── sast_scanner.py                 # [M4] SAST 扫描
│   └── business_scanner.py             # [M5] 业务逻辑
├── reporters/
│   ├── __init__.py
│   ├── base.py                         # [M1] 报告基类
│   ├── terminal.py                     # [M1] 终端输出
│   └── json.py                         # [M7] JSON 输出
├── fixers/
│   ├── __init__.py
│   ├── base.py                         # [M6] 修复基类
│   └── edit_generator.py               # [M6] Edit 生成
├── models.py                           # [M1] 数据模型
├── rule_engine.py                      # [M1] 规则引擎
├── engine.py                           # [M1] 主入口
├── sast_patterns.py                    # [M4] 内置 SAST 模式库
└── requirements.txt                    # [M1] 依赖声明
```

### 8.2 实现顺序（7 个里程碑）

| 里程碑 | 文件 | 说明 | 验证方式 |
|--------|------|------|----------|
| **M1** 🔴 | `models.py`, `rule_engine.py`, `engine.py`, `scanners/base.py`, `scanners/project_probe.py`, `scanners/config_scanner.py`, `reporters/terminal.py`, `.claude/skills/security-review.md`, `rules/django/csrf.yml`, `rules/django/debug-true.yml`, `rules/django/allowed-hosts.yml` | 核心框架 + Django 配置扫描 | 对 crazymusic-backend 运行，应检测到 CSRF 缺失、DEBUG=True、ALLOWED_HOSTS 问题 |
| **M2** 🟠 | `rules/base/*.yml`, `rules/django/cors.yml`, `rules/django/secret-key.yml`, `rules/docker/security.yml` | 配置规则扩展 | 运行 `--quick` 应输出 5+ 配置问题 |
| **M3** 🟠 | `scanners/dependency_scanner.py` | 依赖扫描集成 | 运行 `--focus deps` 应扫描 requirements.txt，列出 CVE |
| **M4** 🟠 | `scanners/sast_scanner.py`, `sast_patterns.py`, `rules/python/*.yml`, `rules/javascript/*.yml` | SAST 扫描 | 运行 `--focus sast` 应在测试代码中检测到 SQL 注入模式 |
| **M5** 🟡 | `scanners/business_scanner.py` | 业务逻辑扫描 | 运行 `--focus business` 应检测到缺乏速率限制、IDOR 风险 |
| **M6** 🟡 | `fixers/*.py` | 交互式修复 | 扫描后应能交互式应用修复 |
| **M7** 🟢 | `reporters/json.py`, `ci-cd/` | CI/CD 集成 | JSON 输出应能被 CI 解析 |

### 8.3 engine.py 主入口

```python
#!/usr/bin/env python3
"""
Security Review Agent — 扫描引擎主入口

用法:
    python engine.py                    # 全量扫描
    python engine.py --quick            # 快速扫描
    python engine.py --focus config     # 仅配置
    python engine.py --output json      # JSON 输出
    python engine.py --diff HEAD~1      # 增量扫描
"""

import argparse
import time
from pathlib import Path

def main():
    args = parse_args()
    root_path = args.path or Path.cwd()
    
    # Phase 1: 项目探针
    probe = ProjectProbe()
    project_info = probe.probe(root_path)
    
    # Phase 2: 并行扫描
    findings = run_parallel_scans(project_info, root_path, args)
    
    # Phase 3: 聚合去重
    findings = deduplicate_and_sort(findings)
    
    # Phase 4: 生成修复
    if not args.no_fix:
        findings = generate_fixes(findings, root_path)
    
    # Phase 5: 输出报告
    report = Report(
        project_name=root_path.name,
        tech_stack=detect_tech_stack(project_info),
        scan_time_seconds=time.time() - start_time,
        dimensions_covered=args.focus or ALL_DIMENSIONS,
        findings=findings,
    )
    
    if args.output == "json":
        reporter = JsonReporter()
    else:
        reporter = TerminalReporter()
    
    print(reporter.generate(report))
    
    # 交互式修复
    if not args.no_fix and not args.output == "json":
        interactive_fix(report)

def run_parallel_scans(project_info, root_path, args):
    """并行运行选中的扫描器"""
    scanners = {
        "dependency": DependencyScanner(),
        "config": ConfigScanner(),
        "sast": SastScanner(),
        "auth": AuthScanner() if hasattr(args, 'focus') else None,
        "business": BusinessScanner(),
    }
    
    # 筛选启用的维度
    if args.focus and args.focus != "all":
        scanners = {k: v for k, v in scanners.items() if k == args.focus or v is None}
    elif args.quick:
        scanners = {k: v for k, v in scanners.items() if k in ("config", "dependency")}
    
    # 串行执行（Claude Code 中改由 Workflow 并行）
    all_findings = []
    for name, scanner in scanners.items():
        if scanner:
            all_findings.extend(scanner.scan(project_info, root_path))
    
    return all_findings
```

---

## 9. 规则加载与匹配流程

```
engine.scan() 调用
  ↓
rule_engine.load_rules()
  ↓ 遍历 rules/**/*.yml
  ↓
rule_engine.filter_rules(project_info)
  ↓ 按 languages + frameworks 筛选
  ↓
for each rule:
  rule.matches(project path)
    ↓
  detect 条件检查:
    file_contains? → grep 文件内容
    file_not_contains? → grep 确认不在
    regex? → 正则匹配
    config_value? → 解析配置值
    comment_or_missing? → 检查注释或不存在
    ↓
  满足条件 → 生成 Finding
    ↓
  不满足 → 跳过
```

---

## 10. 验证方案

### 10.1 对 crazymusic-backend 的验收测试

运行 `/security-review` 应检测到以下问题：

| # | 预期发现 | 严重度 | 验证方法 |
|---|---------|--------|----------|
| 1 | CSRF 中间件缺失 | 🔴 Critical | 检查 `settings.py:33` |
| 2 | SECRET_KEY 硬编码 | 🔴 Critical | 检查 `settings.py:10` |
| 3 | DEBUG=True | 🟠 High | 检查 `settings.py:12` |
| 4 | ALLOWED_HOSTS=['*'] | 🟠 High | 检查 `settings.py:14` |
| 5 | CORS_ALLOW_ALL_ORIGINS=True | 🟠 High | 检查 `settings.py:85` |
| 6 | 缺乏默认角色校验 | 🟡 Medium | 检查 `views.py` 中 `AllowAny` 使用 |
| 7 | SQLite 生产环境 | 🟡 Medium | 检查 `settings.py:62` |
| 8 | Session Cookie Secure 缺失 | 🟡 Medium | 检查 `settings.py:88` |
| 9 | 文件上传未限制 | 🟢 Low | 检查 settings 中缺失的配置 |

### 10.2 单元测试

```python
# tests/test_project_probe.py
def test_detect_python_project():
    probe = ProjectProbe()
    info = probe.probe("tests/fixtures/django-project")
    assert Language.PYTHON in info.languages
    assert "django" in info.frameworks
    assert "pip" in info.dependency_files

# tests/test_rule_engine.py
def test_csrf_rule_match():
    engine = RuleEngine("rules/")
    engine.load_rules()
    findings = engine.apply_rule("django-csrf-disabled", "tests/fixtures/django-project")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL

# tests/test_sast_patterns.py
def test_sql_injection_detect():
    scanner = SastScanner()
    findings = scanner.scan_single_file("tests/fixtures/vulnerable.py")
    assert any("SQL injection" in f.title.lower() for f in findings)
```

### 10.3 测试夹具目录

```
tests/fixtures/
├── django-project/           # 已知有安全问题的 Django 项目
│   ├── settings.py           # DEBUG=True, CSRF 注释, ALLOWED_HOSTS=['*']
│   ├── views.py              # SQL 注入, AllowAny
│   └── requirements.txt      # 有过期依赖
├── express-project/          # 已知有安全问题的 Express 项目
│   ├── app.js                # Helmet 缺失, eval 使用
│   └── package.json          # 有过期依赖
├── vulnerable.py             # 含 SQL 注入/命令注入的代码片段
└── secure.py                 # 安全的代码片段（用于误报验证）
```

### 10.4 运行测试

```bash
# 直接运行 Python 引擎
python engine.py --path e:\crazymusic-front\crazymusic-backend

# 快速模式
python engine.py --path e:\crazymusic-front\crazymusic-backend --quick

# JSON 输出
python engine.py --path e:\crazymusic-front\crazymusic-backend --output json

# Claude Code 中调用
/security-review
```

---

## 附录 A：外部工具集成一览

| 工具 | 用途 | 安装命令 | 安装位置 | JSON 输出模式 | 降级策略 |
|------|------|----------|----------|---------------|----------|
| pip-audit | Python 依赖 CVE | `pip install pip-audit` | venv | `-f json` | `pip list` + 内置 CVE 库 |
| npm audit | Node.js 依赖 | 内置 | 系统 | `--json` | 读取 `package.json` + 内置库 |
| bandit | Python SAST | `pip install bandit` | venv | `-f json` | 内置 SAST_PATTERNS |
| semgrep | 多语言 SAST | `pip install semgrep` | venv | `--json` | bandit 或内置 SAST_PATTERNS |
| govulncheck | Go 依赖 | `go install` | GOPATH | `-json` | 跳过（无降级） |
| cargo-audit | Rust 依赖 | `cargo install` | 系统 | `--json` | 跳过 |
| bundler-audit | Ruby 依赖 | `gem install` | 系统 | JSON 格式 | 跳过 |

## 附录 B：现有参考实现

| 资源 | 路径 | 用途 |
|------|------|------|
| security-auditor.md | `C:\Users\Admin\.claude\plugins\marketplaces\claude-plugins-official\plugins\code-modernization\agents\security-auditor.md` | 参考 Agent 提示词设计 |
| security-guidance 插件 | `C:\Users\Admin\.claude\plugins\marketplaces\claude-plugins-official\plugins\security-guidance\` | 被动安全审查插件（与扫描 Agent 互补） |
| pip-audit v2.10.1 | PyPI `pip-audit==2.10.1` | Python 依赖扫描后端 |
| SKILL.md 格式 | `.claude/skills/<name>/SKILL.md` | Claude Code 技能定义格式 |
