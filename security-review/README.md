# 🔒 Security Review Agent

多维度、自动化的项目安全审查工具。可作为 **Claude Code 技能** (`/security-review`) 或 **独立 CLI** (`python engine.py`) 运行。

---

## 功能

| 维度 | 扫描内容 | 检测项示例 |
|------|----------|-----------|
| ⚙️ **Config** | 框架配置文件安全 | CSRF 缺失、DEBUG=True、CORS 宽松、密钥硬编码 |
| 📦 **Dependency** | 第三方依赖 CVE | pip/npm/Go/Java 已知漏洞 |
| 🔎 **SAST** | 静态代码安全分析 | SQL注入、XSS、命令注入、SSRF、反序列化 |
| 🔑 **Auth** | 认证与授权 | 会话安全、CSRF 保护、权限配置 |
| 💼 **Business** | 业务逻辑安全 | IDOR、速率限制、AllowAny 权限 |

### 覆盖语言与框架

- **Python**: Django, Flask, FastAPI
- **JavaScript/TypeScript**: Express, NestJS, React, Vue, Next.js
- **Go**: Gin, GORM
- **Java**: Spring Boot
- 以及 Ruby, Rust, PHP, C#, Kotlin (基础 SAST)

---

## 快速开始

### 方式 1：Claude Code 技能

```bash
# 全量扫描
/security-review

# 快速扫描（配置 + 依赖）
/security-review --quick

# 单维度聚焦
/security-review --focus config
/security-review --focus sast

# 增量扫描（仅变更文件）
/security-review --diff HEAD~1

# JSON 输出（CI 模式）
/security-review --output json --no-fix
```

### 方式 2：独立 CLI

```bash
# 全量扫描
python engine.py

# 指定项目路径
python engine.py --path /path/to/project

# JSON 输出
python engine.py --output json --no-fix

# Markdown 输出
python engine.py --output markdown --no-fix

# 增量扫描（仅变更文件）
python engine.py --diff HEAD~1

# 仅配置扫描
python engine.py --focus config

# 自动应用修复
python engine.py --apply all          # 全部
python engine.py --apply 1,3,5        # 按编号

# 更新 CVE 缓存（从 OSV.dev 拉取实时数据）
python engine.py --update-cve

# 禁用外部工具（仅内置引擎）
python engine.py --no-external

# SARIF 输出（GitHub Code Scanning 原生格式）
python engine.py --output sarif --no-fix

# 校验所有 YAML 规则的结构
python engine.py --validate-rules
```

> json/markdown/sarif 模式下进度消息走 stderr，stdout 只含报告，适合 CI 管道。`--apply` 只修改有明确编辑方案（search/replacement）的可自动修复项，其余给出建议。终端模式下不带 `--apply` 且 stdin 为 TTY 时，会进入**交互式修复菜单**（输入编号 / a / q）。扫描器并行执行，大项目速度更快。

## 企业级特性

| 特性 | 说明 |
|------|------|
| **审计日志** | 每次扫描/修复写入 `security-audit.log.jsonl`（可用 `SECREVIEW_AUDIT_LOG` 指定路径）：scan_start / scan_complete / fix_applied / fix_skipped 全留痕，含 git commit 与规则版本，可复现 |
| **分级批准** | CRITICAL/HIGH 修复默认跳过，需 `--approve` 或交互确认；LOW/MEDIUM 可直接应用。审计记录被跳过的高危项 |
| **Prompt Injection 防护** | 被扫描的源码/配置视为不可信数据；文件中的指令绝不执行，只做白名单分析操作。skill 与全部扫描 Agent 内置安全边界声明 |

### 方式 3：CI/CD 集成

见 [CI_CD_INTEGRATION.md](CI_CD_INTEGRATION.md) 了解 GitHub Actions 和 GitLab CI 配置。

---

## 文件结构

```
security-review/
├── .claude/
│   ├── agents/              # 8 个 Agent 定义
│   │   ├── project-probe.md       # 项目探针
│   │   ├── config-scanner.md      # 配置安全扫描
│   │   ├── dependency-scanner.md  # 依赖漏洞扫描
│   │   ├── sast-scanner.md        # SAST 代码扫描
│   │   ├── auth-scanner.md        # 认证授权扫描
│   │   ├── business-scanner.md    # 业务逻辑扫描
│   │   ├── aggregator.md          # 聚合去重
│   │   └── report-generator.md    # 报告生成
│   └── skills/
│       └── security-review.md     # 技能入口 + 工作流编排
├── rules/                   # 安全规则 (YAML)
│   ├── base/                      # 通用规则 (3)
│   ├── python/                    # Python (5)
│   ├── django/                    # Django (9) ★
│   ├── javascript/                # JavaScript (3)
│   ├── go/                        # Go (2)
│   ├── java/                      # Java (3)
│   ├── ruby/                      # Ruby (3) ★
│   ├── express/                   # Express (3) ★
│   ├── spring/                    # Spring Boot (3) ★
│   ├── flask/                     # Flask (2) ★
│   ├── terraform/                 # Terraform IaC (3) ★
│   ├── docker/                    # Docker (2) ★
│   ├── k8s/                       # Kubernetes (2)
│   └── cicd/                      # CI/CD (1)
├── tests/                   # 单元测试 (95+ 个)
├── models.py                # 数据模型
├── utils.py                 # 工具函数 (文件/规则/忽略)
├── ast_scanner.py           # Python AST 污点分析 (标准库 ast) ★
├── sast_patterns.py         # 内置 SAST 模式库 (12 类型 × 9+ 语言) ★
├── dependency_db.py         # CVE 数据库 (7 生态) + OSV 实时缓存 ★
├── engine.py                # CLI 入口 ★
├── CI_CD_INTEGRATION.md     # CI/CD 集成文档
└── requirements.txt         # 可选依赖

★ = 本次完善新增/增强
```

---

## 降级策略

| 场景 | 首选方案 | 自动降级 |
|------|---------|----------|
| 依赖扫描 | pip-audit / npm audit | OSV 缓存 → 内置 CVE 数据库 |
| SAST 扫描 (Python) | bandit | AST 污点分析 (`ast_scanner.py`) → 正则模式库 |
| SAST 扫描 (其他语言) | semgrep | 正则模式库 (`sast_patterns.py`) |
| YAML 解析 | PyYAML | 纯 Python 简易解析器 |

无需安装任何外部工具即可运行基础扫描。安装可选工具可获得更准确的结果：

```bash
pip install -r requirements.txt
```

**CVE 实时数据**：`python engine.py --update-cve` 从 [OSV.dev](https://osv.dev) 拉取内置包的最新漏洞到 `.cve-cache.json`（已 gitignore）。缓存存在时 `check_*` 函数优先使用实时数据，否则回退内置静态库。

**Python AST 污点分析**：对 Python 代码自动执行基于标准库 `ast` 的分析——跟踪用户输入（`request.*`、`body` 等）是否流入危险函数，未受污染的调用不再误报，注释/字符串中的代码天然免疫。

---

## 假阳性管理

创建 `.secreview-ignore` 文件来忽略已知误报：

```
# 格式: file_path:line_number:rule_id
src/main.py:42:django-csrf-disabled
src/tests/*:::sast-sql-injection
:::sast-hardcoded-credentials
```

支持通配符 (`*`) 匹配文件和规则 ID。

---

## 测试

```bash
# 运行全部测试
python -m pytest tests/ -v

# 运行指定测试
python -m pytest tests/test_dependency_db.py -v
python -m pytest tests/test_sast_patterns.py -v
python -m pytest tests/test_utils.py -v
```

---

## 许可证

MIT
