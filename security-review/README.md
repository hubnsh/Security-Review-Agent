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
```

> json/markdown 模式下进度消息走 stderr，stdout 只含报告，适合 CI 管道。`--apply` 只修改有明确编辑方案（search/replacement）的可自动修复项，其余给出建议。

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
├── sast_patterns.py         # 内置 SAST 模式库 (12 类型 × 9+ 语言) ★
├── dependency_db.py         # 内置 CVE 数据库 (7 生态) ★
├── engine.py                # CLI 入口 ★
├── CI_CD_INTEGRATION.md     # CI/CD 集成文档
└── requirements.txt         # 可选依赖

★ = 本次完善新增/增强
```

---

## 降级策略

| 场景 | 首选方案 | 自动降级 |
|------|---------|----------|
| 依赖扫描 | pip-audit / npm audit | 内置 CVE 数据库 (`dependency_db.py`) |
| SAST 扫描 | bandit / semgrep | 正则模式库 (`sast_patterns.py`) |
| YAML 解析 | PyYAML | 纯 Python 简易解析器 |

无需安装任何外部工具即可运行基础扫描。安装可选工具可获得更准确的结果：

```bash
pip install -r requirements.txt
```

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
