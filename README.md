# 🔒 Security Review Agent

通用安全审查 Agent — 自动扫描项目依赖/配置/代码/认证/业务逻辑漏洞并提供修复。

## 快速开始

### 调用方式

在 Claude Code 中（需要有 `.claude/skills/` 配置）：

```bash
/security-review                          # 全量扫描（5 个维度）
/security-review --quick                  # 快速扫描
/security-review --focus config           # 仅配置扫描
/security-review --output json --no-fix   # CI 模式
/security-review --apply all              # 扫描后自动修复
```

### 扫描维度

| 维度 | 扫描内容 | 工具依赖 |
|------|----------|----------|
| **Config** | 配置安全（密钥、CORS、CSRF、Debug 等） | 无（YAML 规则） |
| **Dependency** | 依赖漏洞 CVE 扫描 | pip-audit / npm audit（可选） |
| **SAST** | 代码注入（SQL/XSS/命令/SSRF） | bandit（可选） |
| **Auth** | 认证授权（权限、角色、密码策略） | 无 |
| **Business** | 业务逻辑（支付、IDOR、限频） | 无 |

### 输出示例

```
╔═══════════════════════════════════════════════════════╗
║              🔒 Security Review Report                ║
╠═══════════════════════════════════════════════════════╣
║  Project:    crazymusic-backend                       ║
║  Tech Stack: Python + Django                          ║
║  Duration:   12.3s                                   ║
╚═══════════════════════════════════════════════════════╝

| Severity    | Count | Auto-fixable |
|-------------|-------|-------------|
| 🔴 Critical | 3     | 3           |
| 🟠 High     | 5     | 4           |
| 🟡 Medium   | 4     | 1           |
| 🟢 Low      | 2     | 0           |
| **合计**    | **14**| **8**       |
```

## 项目结构

```
agent/security-review/
├── .claude/
│   ├── skills/
│   │   └── security-review.md       # 技能入口，Workflow 编排
│   └── agents/
│       ├── project-probe.md         # Phase 1: 项目探针
│       ├── config-scanner.md        # Phase 2: 配置扫描
│       ├── dependency-scanner.md    # Phase 2: 依赖扫描
│       ├── sast-scanner.md          # Phase 2: SAST 扫描
│       ├── auth-scanner.md          # Phase 2: 认证授权扫描
│       ├── business-scanner.md      # Phase 2: 业务逻辑扫描
│       ├── aggregator.md            # Phase 3: 聚合去重
│       └── report-generator.md      # Phase 5: 报告输出
├── rules/                           # YAML 规则文件（21 个）
│   ├── base/                        # 语言无关（3 个）
│   ├── python/                      # Python 通用（5 个）
│   ├── django/                      # Django 特定（8 个）
│   ├── javascript/                  # JS/TS 通用（3 个）
│   ├── docker/                      # Docker（1 个）
│   └── cicd/                        # CI/CD（1 个）
├── models.py                        # 数据模型
├── sast_patterns.py                 # SAST 模式库（11 种漏洞 × 7 语言）
├── dependency_db.py                 # CVE 对照表（18 个包）
├── utils.py                         # 工具函数
├── requirements.txt                 # 可选依赖（pip-audit, bandit）
└── README.md                        # 本文档
```

## 规则文件

21 个 YAML 规则覆盖以下检查项：

| 类别 | 规则 | 严重度 |
|------|------|--------|
| 🔴 硬编码密钥 | secrets-in-code.yml | CRITICAL |
| 🔴 CSRF 缺失 | django/csrf.yml | CRITICAL |
| 🔴 SECRET_KEY 硬编码 | django/secret-key.yml | CRITICAL |
| 🔴 SQL 注入 | python/sql-injection.yml | CRITICAL |
| 🔴 命令注入 | python/command-injection.yml | CRITICAL |
| 🔴 不安全反序列化 | python/unsafe-deserialization.yml | CRITICAL |
| 🟠 Debug 模式 | base/debug-mode.yml | HIGH |
| 🟠 ALLOWED_HOSTS | django/allowed-hosts.yml | HIGH |
| 🟠 CORS 配置 | django/cors.yml | HIGH |
| 🟠 Session Cookie | django/session-cookie.yml | HIGH |
| 🟠 默认权限 AllowAny | django/auth-config.yml | HIGH |
| 🟠 XSS | javascript/xss.yml | HIGH |
| 🟠 原型污染 | javascript/prototype-pollution.yml | HIGH |
| 🟠 eval() | javascript/eval-usage.yml | HIGH |
| 🟠 路径遍历 | python/path-traversal.yml | HIGH |
| 🟠 SSRF | python/ssrf.yml | HIGH |
| 🟠 CI/CD 密钥泄露 | cicd/secrets-in-ci.yml | HIGH |
| 🟡 弱加密 | base/weak-crypto.yml | MEDIUM |
| 🟡 SQLite 生产 | django/database.yml | MEDIUM |
| 🟡 Docker Root 用户 | docker/root-user.yml | MEDIUM |

## 降级策略

外部工具始终是可选依赖。缺失时自动降级：

| 工具 | 用途 | 降级方案 |
|------|------|----------|
| `pip-audit` | Python CVE 扫描 | `dependency_db.py` 内置 CVE 表 |
| `npm audit` | Node.js CVE 扫描 | `dependency_db.py` 内置 CVE 表 |
| `bandit` | Python SAST | `sast_patterns.py` 正则模式库 |

## 数据模型

核心类在 `models.py` 中：

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **ScanDimension**: config / dependency / sast / auth / business
- **Finding**: id, dimension, severity, title, description, cwe, owasp, file_path, line, fixes
- **Fix**: description, type, effort, edit_operations
- **EditOperation**: file, old_string, new_string
- **Report**: project_name, tech_stack, scan_time, findings, stats
- **ProbeResult**: languages, frameworks, dep_managers, rules_to_load

## 开发

### 添加新规则

在 `rules/` 对应目录下创建 YAML 文件：

```yaml
# rules/python/my-rule.yml
id: unique-rule-id
name: Rule Display Name
description: Rule description
severity: high
cwe: CWE-XXX
owasp: "A0X:20XX"
languages: [python]

detect:
  - type: regex_in_file
    pattern: "dangerous_pattern"

fix:
  - type: edit
    file: "**/*.py"
    old: "bad_code"
    new: "good_code"
    effort: low
```

### 验证规则

```bash
python -c "import yaml; yaml.safe_load(open('rules/python/my-rule.yml'))"
```

### 运行单元测试

```bash
python -c "
import models
import sast_patterns
import dependency_db
import utils
print('All modules loaded OK')
"
```

## License

MIT
