# 🔒 Security Review Agent — 需求文档

> **版本**：v2.0  
> **日期**：2026-07-27  
> **状态**：定稿  
> **定位**：通用安全审查 Agent，不绑定任何特定项目或技术栈

---

## 目录

- [1. 概述](#1-概述)
- [2. 扫描维度](#2-扫描维度)
- [3. 工作流程](#3-工作流程)
- [4. 输出报告格式](#4-输出报告格式)
- [5. 技术方案](#5-技术方案)
- [6. 交互与 UX](#6-交互与-ux)
- [7. 非功能性需求](#7-非功能性需求)
- [8. 开发计划](#8-开发计划)
- [9. 项目结构建议](#9-项目结构建议)

---

## 1. 概述

### 1.1 背景

安全审查是软件开发的重要环节，但手动审查存在效率低、覆盖不全、标准不统一等问题。开发者需要一个自动化的安全 Agent，能对**任意项目**进行系统性的安全扫描，发现漏洞并提供可操作的修复方案。

### 1.2 目标

构建一个通用的 Security Review Agent，可通过 `/security-review` 命令在任何 Claude Code 工作区中调用，自动识别项目技术栈、执行多维安全扫描、输出结构化报告并提供交互式修复。

### 1.3 设计原则

| 原则 | 说明 |
|------|------|
| **技术栈无关** | 自动检测项目语言和框架，加载对应规则集，无需手动配置 |
| **渐进式扫描** | 从快速检查到深度分析，用户可根据需要选择扫描深度 |
| **工具可选** | 依赖外部工具（pip-audit、npm audit 等），但缺失时自动降级 |
| **可交互** | 用户可逐条选择是否应用修复，Agent 不擅自修改代码 |
| **可扩展** | 规则以 YAML 文件热加载，用户可添加自定义规则 |

### 1.4 适用范围

| 维度 | 覆盖 |
|------|------|
| **语言** | Python、JavaScript / TypeScript、Go、Java / Kotlin、Ruby、Rust、PHP、C# |
| **框架** | Django、Flask、FastAPI、Express、NestJS、Spring Boot、Rails、Laravel、ASP.NET |
| **依赖格式** | `requirements.txt`、`pyproject.toml`、`Pipfile`、`package.json`、`go.mod`、`pom.xml`、`build.gradle`、`Gemfile`、`Cargo.toml`、`composer.json` |
| **配置文件** | Django settings、Spring application.yml、Rails credentials、Dockerfile、docker-compose.yml、K8s manifest、Terraform、CloudFormation |
| **CI/CD** | GitHub Actions、GitLab CI、Jenkinsfile、CircleCI config |

---

## 2. 扫描维度

### 2.1 依赖漏洞扫描（Dependency CVE）

自动识别项目的依赖管理工具并执行对应扫描。

| 生态 | 依赖文件 | 扫描工具 |
|------|----------|----------|
| Python | `requirements.txt` / `pyproject.toml` / `Pipfile` | `pip-audit` / `safety` |
| Node.js | `package.json` / `package-lock.json` / `yarn.lock` | `npm audit` / `yarn audit` / `pnpm audit` |
| Go | `go.mod` / `go.sum` | `govulncheck` |
| Java | `pom.xml` / `build.gradle` | `mvn dependency-check` / `gradle audit` |
| Ruby | `Gemfile` / `Gemfile.lock` | `bundler-audit` |
| Rust | `Cargo.toml` / `Cargo.lock` | `cargo audit` |
| PHP | `composer.json` / `composer.lock` | `composer audit` |

**输出格式**：

```
📦 依赖漏洞 (3 个)
├─ CVE-2024-XXXXX (CRITICAL)  django < 5.2.x  
│   ├─ 描述: 描述及影响
│   └─ 修复: pip install "django>=5.2.0"
├─ CVE-2024-XXXXX (HIGH)     lodash < 4.17.21  
│   ├─ 描述: 描述及影响
│   └─ 修复: npm install lodash@4.17.21
└─ ...
```

### 2.2 配置安全审查（Config Security）

| 类别 | 检查项 | 示例问题 |
|------|--------|----------|
| **通用** | Debug/Dev 模式开启 | `DEBUG=True`、`NODE_ENV=development` |
| | 密钥/凭证硬编码 | `SECRET_KEY`、`API_KEY`、密码在源码中 |
| | 宽松的 CORS | `Access-Control-Allow-Origin: *` |
| | 缺失 HTTPS 强制 | `SECURE_SSL_REDIRECT` 未配置 |
| | 宽松的 Host 头校验 | `ALLOWED_HOSTS=['*']` |
| **Python/Django** | CSRF 中间件被注释 | `CsrfViewMiddleware` 被注释 |
| | SQLite3 用于生产 | `ENGINE: sqlite3` |
| | Session 安全 Cookie 未配置 | `SESSION_COOKIE_SECURE` 缺失 |
| | 文件上传无限制 | 未配置 `FILE_UPLOAD_MAX_MEMORY_SIZE` |
| **Node.js/Express** | Helmet 中间件缺失 | 无安全头中间件 |
| | 速率限制缺失 | `express-rate-limit` 未配置 |
| | 不安全的 `eval` | `eval(user_input)` |
| **Go** | 不安全的 `crypto` 使用 | 使用 `md5`、`sha1` 而非 `bcrypt` |
| **Java/Spring** | Actuator 暴露 | 未认证的 `/actuator/*` 端点 |
| **Ruby/Rails** | `secret_key_base` 硬编码 | 未从环境变量读取 |
| **通用 Docker** | 容器以 root 运行 | `USER root` 或未指定 USER |
| | 基础镜像未固定版本 | `FROM node:latest` |

### 2.3 静态代码安全分析（SAST）

| 类别 | 检测模式 | 适用语言 |
|------|----------|----------|
| **SQL 注入** | 原生 SQL 拼接、ORM 特殊方法 | 所有语言 |
| | `raw()`、`extra()`、`execute()` 动态参数 | Python |
| | ORM 中的原始查询 | Java(JPA)、Go(GORM) |
| **XSS** | 模板未转义输出 | `{{ \|safe }}`、`dangerouslySetInnerHTML`、`v-html` |
| | `innerHTML` 直接赋值 | JS/TS |
| **命令注入** | `os.system()`、`subprocess` 拼接 | Python |
| | `exec()`、`child_process.exec()` | JS/TS |
| **路径遍历** | 用户输入拼接文件路径 | `os.path.join(path, user_input)` |
| | `sendFile(user_input)` | Express |
| **不安全的反序列化** | `pickle.loads()`、`yaml.load()` | Python |
| | `JSON.parse()` 无校验 | JS/TS |
| | `ObjectInputStream.readObject()` | Java |
| **SSRF** | 用户输入传入 URL 请求 | `requests.get(input)`、`fetch(input)` |
| | `UrlConnection.openConnection()` | Java |
| **XXE** | XML 解析器配置不当 | `xml.etree.ElementTree.parse()` |
| | XXE 攻击可能 | Java `DocumentBuilder` |
| **原型污染** | 不安全的对象合并 | `Object.assign()`、`_.merge()` |
| **硬编码凭据** | 密钥/密码在源码中 | 正则匹配 `password\s*=\s*['\"]` |
| **不安全的随机数** | `Math.random()` 用于安全场景 | JS/TS |
| | `random` 模块用于密码学 | Python |

### 2.4 业务逻辑安全审查（Business Logic Security）

| 类别 | 检查项 | 示例 |
|------|--------|------|
| **认证** | 无登录频率限制 | 登录接口不限频 |
| | 注册无验证码 | 直接创建用户 |
| | 密码策略过弱 | 仅校验长度 |
| | Token 在 URL 中传输 | `?token=xxx` |
| **授权** | 仅校验登录未校验角色 | 管理员接口任何人都能访问 |
| | IDOR 直接对象引用 | 传 ID 即可操作他人资源 |
| | 批量操作无拥有权校验 | 删除/更新未校验 owner |
| **输入验证** | 无参数校验或校验不严 | SQL、XSS、类型混淆 |
| | 文件上传无限制 | 类型/大小/数量均未限制 |
| **金融/支付** | 金额用户可指定 | 客户端传入价格 |
| | 到账无三方验证 | 客户端确认即可 |
| | 缺少防重入/重放 | 同一请求可重复扣款 |
| **会话管理** | Session key 在 URL 中 | SID 泄露风险 |
| | 无 Token 过期/刷新 | JWT 无过期时间 |
| | 退出登录未销毁服务端 Session | 退出后 Token 仍可用 |
| **日志与监控** | 敏感信息被日志记录 | 密码、Token 打印到日志 |
| | 无审计日志 | 关键操作无可追溯记录 |

---

## 3. 工作流程

```
┌──────────────────────────────────────────────────────────┐
│ 用户输入: /security-review [options]                     │
└──────────────────┬───────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 1: 项目探针 (Project Probe)                        │
│  ├─ 扫描文件树，识别项目类型                             │
│  ├─ 检测语言、框架、依赖管理工具                         │
│  ├─ 读取关键配置文件                                    │
│  └─ 加载对应规则集                                      │
└──────────────────┬───────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 2: 并行扫描 (Parallel Scan)                        │
│  ├─ Agent A: 依赖漏洞扫描                               │
│  ├─ Agent B: 配置安全审查                                │
│  ├─ Agent C: SAST 注入类扫描                            │
│  ├─ Agent D: 认证授权扫描                                │
│  └─ Agent E: 业务逻辑扫描                                │
└──────────────────┬───────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 3: 聚合去重 (Aggregate & Dedup)                    │
│  ├─ Flatten + 去重相同漏洞                               │
│  ├─ 按严重度排序 (CRITICAL > HIGH > MEDIUM > LOW > INFO) │
│  └─ 交叉验证疑似误报                                     │
└──────────────────┬───────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 4: 生成修复 (Generate Fixes)                       │
│  ├─ 为每个漏洞生成修复代码 (Edit/Diff 格式)              │
│  ├─ 高风险漏洞提供 2+ 种修复方案                         │
│  └─ 安全改进路线图                                      │
└──────────────────┬───────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 5: 输出报告 (Output Report)                        │
│  ├─ 终端摘要 (彩色 Markdown 表格)                        │
│  ├─ 详细发现列表 (含文件、行号、攻击场景)                │
│  ├─ 修复方案 (可点击的 Edit 操作)                        │
│  └─ 交互式修复入口                                      │
└──────────────────────────────────────────────────────────┘
```

### Phase 1 — 项目探针

自动探测当前工作区的项目信息，无需任何手动配置：

| 探测项 | 检测方法 | 结果影响 |
|--------|----------|----------|
| 语言 | 检查文件后缀分布（`.py` / `.js` / `.ts` / `.go` / `.java` 等） | 加载对应语言规则 |
| 框架 | 检查 `settings.py`、`package.json` 中的依赖、框架特征文件 | 加载框架特定规则 |
| 依赖管理 | 检查 `requirements.txt`、`package.json`、`go.mod` 等 | 选择依赖扫描工具 |
| 版本控制 | 检查 `.git` 目录 | 可结合 git diff 只扫描变更 |
| 前端/后端 | 检查模板文件、前端构建配置 | 调整扫描侧重 |

#### 框架自动识别示例

```
文件探测结果:
├─ 📄 *.py × 48             → Python 项目
├─ 📄 Django settings.py     → Django 框架
├─ 📄 requirements.txt       → pip 依赖管理
├─ 📄 Dockerfile             → 容器化部署
└─ 📄 Makefile               → 自定义构建

加载规则集:
├─ python-base.yml
├─ django-config.yml
├─ python-sast.yml
└─ docker-security.yml
```

### Phase 2 — 并行扫描

使用 Claude Code 的多 Agent 能力对不同维度进行并行扫描。每个扫描维度是一个独立 Agent，互不依赖。

```
时间线:
├─ Agent A (依赖) ───────── 3s ────── 结果
├─ Agent B (配置) ───────── 5s ────── 结果     ← 最长路径
├─ Agent C (SAST)  ──────── 4s ────── 结果
├─ Agent D (认证)  ──────── 2s ────── 结果
└─ Agent E (业务)  ──────── 4s ────── 结果

总耗时: 5s (取决于最慢 Agent)
```

### Phase 3 — 聚合去重

合并来自不同维度的结果，避免重复报告：

1. **去重**：相同文件 + 相同行号 + 相同漏洞类型 → 合并
2. **排序**：CRITICAL > HIGH > MEDIUM > LOW > INFO
3. **验证**：对疑似误报，追加验证步骤确认

### Phase 4 — 生成修复方案

每个漏洞生成可直接执行的修复：

- **自动修复**（配置类）：修改 `settings.py`、`application.yml` 等
- **代码修复**（安全缺陷）：替换危险函数、添加校验逻辑
- **架构方案**（业务逻辑）：需要在更高层面重构的，提供解决方案文档

### Phase 5 — 输出报告

以结构化 Markdown 输出报告，同时提供交互式修复入口（详见第 4 节）。

---

## 4. 输出报告格式

### 4.1 终端摘要

```
╔═══════════════════════════════════════════════════════╗
║              🔒 Security Review Report                ║
╠═══════════════════════════════════════════════════════╣
║  Project:        crazymusic-backend                   ║
║  Tech Stack:     Python + Django + SQLite             ║
║  Scan Depth:     Full (5/5 dimensions)                ║
╚═══════════════════════════════════════════════════════╝

  🔴 Critical:  3    🟠 High:  5    🟡 Medium:  4    🟢 Low:  2

  ┌─────────────────────┬──────┬──────────┬──────────┐
  │ Dimension           │  🔴  │  🟠🟡🟢  │  Total   │
  ├─────────────────────┼──────┼──────────┼──────────┤
  │ Dependency CVE      │  1   │   2      │   3      │
  │ Config Security     │  2   │   3      │   5      │
  │ SAST Injection      │  0   │   1      │   1      │
  │ Auth & Access Ctrl  │  0   │   2      │   2      │
  │ Business Logic      │  0   │   1      │   3      │
  └─────────────────────┴──────┴──────────┴──────────┘

  ⚡ 耗时: 12.3s  |  🛠 可自动修复: 8/14
```

### 4.2 每个发现的详细格式

```text
## 🔴 CRITICAL: CSRF 防护缺失

**文件**: `crazymusic_backend/settings.py:33`
**维度**: Config Security
**CWE**:  CWE-352 (Cross-Site Request Forgery)
**OWASP**: A01:2021 — Broken Access Control

**风险**: CSRF 中间件被注释，所有 POST 请求无 CSRF 保护，
          易受跨站请求伪造攻击。

**攻击场景**: 攻击者构造恶意页面，诱导已登录用户提交表单，
              可执行任意操作（如修改密码、创建订单等）。

**修复方案**:
```python
# 恢复 CSRF 中间件
MIDDLEWARE = [
    ...
    'django.middleware.csrf.CsrfViewMiddleware',  # 取消注释
    ...
]
# 对需要回调的 API 端点用 @csrf_exempt 按需豁免
```

**替代方案**: 如果是 SPA + API 后端，可通过 Token 认证替代
**修复工作量**: 5 分钟
**自动修复**: ✅ 是 (Edit)
```

### 4.3 交互式修复入口

扫描结束后，Agent 提供交互式选项：

```
🛠 是否应用以下修复? (输入编号、范围或 all)
  分类:
    [c] 仅应用配置类修复 (5 项)
    [s] 仅应用 SAST 代码修复 (1 项)
  逐条:
    [1] 🔴 恢复 CSRF 中间件
    [2] 🔴 将 SECRET_KEY 移到环境变量
    [3] 🟠 设置 DEBUG=False
    [4] 🟠 限制 CORS 域名白名单
    ...
  全部:
    [all] 应用全部自动修复 (8 项)
    [q]  退出

请输入 > _
```

---

## 5. 技术方案

### 5.1 项目探针机制

项目探针是 Agent 的第一步，通过检测特征文件自动识别技术栈：

```yaml
# probes/language-probes.yml
probes:
  - language: python
    indicators:
      - "**/*.py"
      - "requirements.txt"
      - "pyproject.toml"
      - "setup.py"
      - "Pipfile"
  - language: javascript
    indicators:
      - "**/*.js"
      - "package.json"
    frameworks:
      express: ["express"]
      nest: ["@nestjs/core"]
      react: ["react"]
      vue: ["vue"]
  - language: typescript
    indicators:
      - "**/*.ts"
      - "package.json" (has typescript dep)
  - language: go
    indicators:
      - "**/*.go"
      - "go.mod"
  - language: java
    indicators:
      - "**/*.java"
      - "pom.xml"
      - "build.gradle"
```

### 5.2 规则引擎

Agent 的核心是 YAML 规则文件系统，规则按语言和框架组织：

```
rules/
├── base/                            # 语言无关的基础规则
│   ├── secrets-in-code.yml          # 硬编码密钥检测
│   ├── weak-crypto.yml              # 弱加密算法
│   └── debug-mode.yml               # Debug 模式检测
├── python/                          # Python 通用规则
│   ├── sql-injection.yml            # SQL 注入
│   ├── command-injection.yml        # 命令注入
│   ├── unsafe-deserialization.yml   # 不安全反序列化
│   ├── path-traversal.yml           # 路径遍历
│   └── ssrf.yml                     # SSRF
├── django/                          # Django 特定规则
│   ├── csrf.yml                     # CSRF 中间件检查
│   ├── debug-True.yml               # DEBUG 模式
│   ├── allowed-hosts.yml            # ALLOWED_HOSTS
│   ├── cors.yml                     # CORS 配置
│   └── secret-key.yml               # SECRET_KEY
├── javascript/                      # JS/TS 通用规则
│   ├── xss.yml                      # XSS
│   ├── prototype-pollution.yml      # 原型污染
│   └── eval-usage.yml               # eval 使用
├── express/                         # Express 特定规则
│   ├── helmet-missing.yml           # Helmet 中间件缺失
│   └── rate-limit.yml               # 速率限制
├── go/                              # Go 规则
│   ├── sql-injection.yml
│   └── weak-hash.yml
├── java/                            # Java 规则
│   ├── actuator-exposure.yml
│   └── xxe.yml
├── docker/                          # Docker 安全规则
│   ├── root-user.yml
│   └── pin-version.yml
└── cicd/                            # CI/CD 安全规则
    ├── secrets-in-ci.yml
    └── no-pin-actions.yml
```

#### 规则格式示例

```yaml
# rules/django/csrf.yml
id: django-csrf-disabled
name: CSRF Middleware Disabled
description: Detects when Django's CSRF middleware is commented out or missing
severity: critical
cwe: CWE-352
owasp: "A01:2021"
languages: [python]
frameworks: [django]

detect:
  - type: file_not_contains
    path: "**/settings.py"
    pattern: "CsrfViewMiddleware"
  - type: file_contains
    path: "**/settings.py"
    pattern: "MIDDLEWARE"

fix:
  - type: uncomment
    file: "**/settings.py"
    search: "#.*CsrfViewMiddleware"
    replacement: "    'django.middleware.csrf.CsrfViewMiddleware',"
  - type: insert_after
    file: "**/settings.py"
    anchor: "MIDDLEWARE = \\["
    text: "    'django.middleware.csrf.CsrfViewMiddleware',"
    position: after_opening_bracket
```

```yaml
# rules/base/secrets-in-code.yml
id: hardcoded-secret-key
name: Hardcoded Secret/Key
description: Detects hardcoded secrets, API keys, passwords in source code
severity: critical
cwe: CWE-798
languages: [python, javascript, go, java, ruby, php, rust]

detect:
  - type: regex
    pattern: '(SECRET_[A-Z_]+\s*[=:]\s*["'"'"'][^"'"'"']+["'"'"'])'
    exclude_extensions: [.env, .env.example, .md, .txt, .yaml, .yml]
    exclude_paths: ["**/node_modules/**", "**/venv/**", "**/.git/**"]

fix:
  - type: replace_with_env_var
    suggestion: "Move to environment variable (e.g., .env file) and reference via os.getenv() / process.env"
  - type: add_to_gitignore
    content: ".env"
```

### 5.3 SAST 模式匹配（内置回退）

当 `bandit`、`semgrep` 等外部工具不可用时，Agent 使用内置的正则模式匹配：

```python
# 内置 SAST 规则（engine 降级模式）
SAST_PATTERNS = {
    "sql-injection": {
        "python": [
            (r"\.raw\(\s*f[\"']", "Django raw query with f-string (SQLi risk)"),
            (r"\.extra\(\s*.*where\s*=.*[\"']\s*\+", "Django extra() with string concatenation"),
            (r"cursor\.execute\(\s*f[\"']", "Raw cursor execute with f-string (SQLi)"),
            (r"execute\([\"'].*\%[\(s%d]", "SQL execute with % formatting (SQLi)"),
        ],
        "javascript": [
            (r"db\.\w+\.\$where\(\s*[\"']\s*\+", "MongoDB $where with concatenation (NoSQLi)"),
            (r"SELECT.*\+(?:req\.|res\.)", "SQL concatenation with request data"),
        ],
        "go": [
            (r"\.Raw\(\s*f[\"']", "GORM raw query with f-string (SQLi)"),
            (r"\.Exec\(\s*f[\"']", "SQL Exec with f-string (SQLi)"),
        ],
        "java": [
            (r"Statement\.executeQuery\(\s*[\"']", "Raw Statement (use PreparedStatement)"),
            (r"\+\s*request\.getParameter", "SQL concatenation with request param"),
        ],
    },
    "command-injection": {
        "python": [
            (r"os\.system\(\s*f[\"']", "Command injection via f-string in os.system()"),
            (r"subprocess\.[a-zA-Z]+\(\s*f[\"']", "Command injection in subprocess"),
            (r"subprocess\.[a-zA-Z]+\([\"'].*\+.*(?:request|input|param)", "Subprocess with user input"),
        ],
        "javascript": [
            (r"exec\(\s*f[\"']", "Command injection in exec()"),
            (r"exec\(\s*[\"'].*\+.*(?:req\.|body\.|query\.)", "Exec with user input"),
        ],
    },
    "path-traversal": {
        "python": [
            (r"open\(\s*os\.path\.join\([^)]*,\s*(?:request|user|input|filepath|filename)",
             "Path traversal: user input in file path"),
        ],
        "javascript": [
            (r"res\.sendFile\(\s*(?:req\.|body\.|query\.)",
             "Path traversal risk in sendFile()"),
            (r"fs\.(readFile|writeFile|unlink|rename)\(\s*(?:req\.|body\.|query\.)",
             "Path traversal in fs operation"),
        ],
    },
}
```

### 5.4 外部工具集成

所有外部工具均为可选，缺失时 Agent 自动降级：

```
┌─ 尝试调用外部工具 ─────────────────────────────┐
│                                                 │
│  pip-audit → 可用?                              │
│  ├─ ✅ → 执行并解析结构化输出                    │
│  └─ ❌ → 降级模式：pip-audit not found           │
│          ├─ pip list 获取已安装包版本            │
│          └─ 匹配内置 CVE 数据库                  │
│                                                 │
│  bandit → 可用?                                 │
│  ├─ ✅ → 执行并解析 JSON 输出                   │
│  └─ ❌ → 降级模式：使用内置 SAST_PATTERNS       │
│                                                 │
│  semgrep → 可用?                                │
│  ├─ ✅ → 加载规则 + 执行                        │
│  └─ ❌ → 跳过（SAST 降级已覆盖）                │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## 6. 交互与 UX

### 6.1 命令格式

```bash
/security-review                          # 默认：全量扫描
/security-review --quick                  # 快速扫描（仅配置 + 依赖）
/security-review --focus config           # 仅检查配置
/security-review --focus deps             # 仅检查依赖
/security-review --focus sast             # 仅静态代码扫描
/security-review --focus auth             # 仅认证授权
/security-review --focus business         # 仅业务逻辑
/security-review --apply 1,3,5            # 扫描后自动应用指定修复
/security-review --apply all              # 扫描后自动应用全部修复
/security-review --no-fix                 # 只输出报告，不生成修复
/security-review --output json            # JSON 格式输出
/security-review --diff HEAD~1           # 仅扫描近一次提交的变更
/security-review --diff main             # 扫描与 main 分支的差异
```

### 6.2 选项说明

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `--quick` | flag | false | 跳过 SAST 和业务逻辑扫描 |
| `--focus` | string | all | 限定扫描范围 |
| `--apply` | string | - | 自动应用修复（编号列表或 `all`） |
| `--no-fix` | flag | false | 仅生成报告 |
| `--output` | string | terminal | 输出格式（terminal / json / markdown） |
| `--diff` | string | - | Git ref，仅扫描与 ref 的差异代码 |

### 6.3 扫描深度分级

用户可通过 `--quick` 和 `--focus` 控制扫描深度：

| 模式 | 执行维度 | 耗时估计 | 适用场景 |
|------|----------|----------|----------|
| `--quick` | 配置 + 依赖 | < 5s | 快速检查、CI 预检 |
| 默认（无参数） | 全部 5 维度 | 10-30s | 日常开发 |
| `--focus sast` | 仅 SAST | 5-15s | 针对具体维度的深度扫描 |
| `--focus auth` | 仅认证授权 | 3-10s | 审计新加的认证逻辑 |

### 6.4 交互式修复流程

```
🛠 应用修复 — 共 8 项可自动修复

选择方案:
  [1] 🔴 CRITICAL: 恢复 CSRF 中间件
      └→ crazymusic_backend/settings.py:33 取消注释 CsrfViewMiddleware

  [2] 🔴 CRITICAL: 将 SECRET_KEY 移到环境变量
      └→ 方案 A: 从 settings.py 移除，改为 os.getenv('DJANGO_SECRET_KEY')
      └→ 方案 B: 添加 .env 文件模板

  [3] 🟠 HIGH: 设置 DEBUG=False
      └→ crazymusic_backend/settings.py:12 修改

输入编号(多个用逗号分隔), [c]配置类, [a]全部, [q]退出: _
```

---

## 7. 非功能性需求

| 需求 | 要求 |
|------|------|
| **语言无关** | 自动识别项目技术栈，无需手动指定语言或框架 |
| **性能** | 全量扫描 < 30s（~1000 文件），快速扫描 < 5s |
| **准确率** | 规则引擎误报率 < 20%，通过多 Agent 交叉验证 |
| **健壮性** | 外部工具不可用时自动降级，不因单维度失败而中止 |
| **可扩展** | 规则以 YAML 热加载，用户可添加自定义规则 |
| **安全性** | Agent 不执行未经用户确认的修复操作 |
| **可重复** | 相同代码多次扫描结果一致（无随机性） |
| **可集成** | 支持 JSON 输出，可集成到 GitHub Actions、GitLab CI 等 |
| **增量扫描** | 支持 `--diff` 仅扫描代码变更部分，适用于 CI 场景 |

---

## 8. 开发计划

### 8.1 里程碑

| 里程碑 | 内容 | 预估 | 编号 |
|--------|------|------|------|
| **M1: 核心框架** | 项目探针 + 规则加载 + 扫描引擎 + 报告输出 | 2 天 | M1 |
| **M2: 配置扫描** | 通用 + Python/Django + Node/Express + Docker 规则 | 2 天 | M2 |
| **M3: 依赖扫描** | 多生态工具集成 + 降级模式 + CVE 格式解析 | 2 天 | M3 |
| **M4: SAST 扫描** | 注入类规则（SQL/XSS/命令注入/路径遍历/SSRF） | 2 天 | M4 |
| **M5: 业务逻辑** | 认证授权 + 支付安全 + 会话管理规则 | 1 天 | M5 |
| **M6: 交互修复** | 交互式修复流程 + 自动应用 + 多种方案选择 | 1 天 | M6 |
| **M7: CI/CD 集成** | JSON 输出 + GitHub Action + `--diff` 增量 | 1 天 | M7 |

### 8.2 分阶段任务

#### M1: 核心框架

- [ ] 实现项目探针（`probe.py`）：根据文件分布检测语言/框架/依赖管理工具
- [ ] 实现规则引擎（`rule_engine.py`）：加载 YAML 规则文件，匹配文件内容
- [ ] 实现扫描模型（`models.py`）：`Finding`、`Fix`、`Report`、`Severity` 数据类
- [ ] 实现引擎主入口（`engine.py`）：协调 Phase 1-5 流程
- [ ] 实现终端报告输出（`reporters/terminal.py`）：彩色 Markdown 表格
- [ ] 实现 JSON 报告输出（`reporters/json.py`）：结构化 JSON

#### M2: 配置扫描

- [ ] 基础规则：硬编码密钥检测、Debug 模式检测、CORS 配置
- [ ] Python/Django 规则：CSRF、DEBUG、ALLOWED_HOSTS、SECRET_KEY、Session 配置
- [ ] Node/Express 规则：Helmet 中间件、速率限制、CORS 配置
- [ ] Docker 规则：Root 用户、镜像版本固定、健康检查缺失

#### M3: 依赖扫描

- [ ] Python 依赖：pip-audit 集成 + 降级（`pip list` + 内置 CVE 库）
- [ ] Node 依赖：npm audit / yarn audit 集成 + 降级
- [ ] Go 依赖：govulncheck 集成（可选）
- [ ] Java/Maven 依赖：mvn dependency-check（可选）

#### M4: SAST 扫描

- [ ] Python SAST: SQL 注入、命令注入、路径遍历、反序列化、SSRF
- [ ] JS/TS SAST: XSS、原型污染、eval、命令注入
- [ ] Java SAST: XXE、SQL 注入、反序列化

#### M5: 业务逻辑扫描

- [ ] 认证缺陷：登录限频、密码策略、Token 管理
- [ ] 授权缺陷：角色校验缺失、IDOR、越权
- [ ] 支付安全：金额篡改、到账确认、重放攻击

#### M6: 交互修复

- [ ] 生成修复方案：`Edit` 操作封装
- [ ] 交互式流程：用户选择 → 确认 → 执行
- [ ] 批量应用：配置类批量修复、按维度修复

#### M7: CI/CD 集成

- [ ] JSON 输出格式标准化
- [ ] GitHub Action 封装
- [ ] `--diff` 增量扫描

---

## 9. 项目结构建议

```
agent/security-review/
├── .claude/
│   └── skills/
│       └── security-review.md          # Claude Code Agent 技能定义
├── rules/                              # 安全规则 (YAML)
│   ├── base/                           # 语言无关通用规则
│   │   ├── secrets-in-code.yml         # 硬编码密钥
│   │   ├── weak-crypto.yml             # 弱加密算法
│   │   └── debug-mode.yml              # Debug/Dev 模式
│   ├── python/                         # Python 通用规则
│   │   ├── sql-injection.yml           # SQL 注入
│   │   ├── command-injection.yml       # 命令注入
│   │   ├── unsafe-deserialization.yml  # 不安全反序列化
│   │   ├── path-traversal.yml          # 路径遍历
│   │   └── ssrf.yml                    # SSRF
│   ├── django/                         # Django 特定规则
│   │   ├── csrf.yml
│   │   ├── debug-True.yml
│   │   ├── allowed-hosts.yml
│   │   └── secret-key.yml
│   ├── javascript/                     # JS/TS 通用规则
│   │   ├── xss.yml
│   │   ├── prototype-pollution.yml
│   │   └── eval-usage.yml
│   ├── express/                        # Express 特定规则
│   │   ├── helmet-missing.yml
│   │   └── rate-limit.yml
│   ├── go/                             # Go 规则
│   │   ├── sql-injection.yml
│   │   └── weak-hash.yml
│   ├── java/                           # Java 规则
│   │   ├── actuator-exposure.yml
│   │   └── xxe.yml
│   ├── docker/                         # Docker 安全规则
│   │   └── root-user.yml
│   └── cicd/                           # CI/CD 安全规则
│       └── secrets-in-ci.yml
├── scanners/                           # 扫描器实现
│   ├── __init__.py
│   ├── base.py                         # 扫描器基类 (AbstractScanner)
│   ├── project_probe.py                # 项目探针 (Phase 1)
│   ├── dependency_scanner.py           # 依赖漏洞扫描
│   ├── config_scanner.py               # 配置安全审查
│   ├── sast_scanner.py                 # 静态代码扫描
│   └── business_scanner.py             # 业务逻辑扫描
├── reporters/                          # 报告生成
│   ├── __init__.py
│   ├── base.py                         # 报告基类
│   ├── terminal.py                     # 终端彩色 Markdown 输出
│   └── json.py                         # JSON 格式输出
├── fixers/                             # 修复引擎
│   ├── __init__.py
│   ├── base.py                         # 修复基类
│   └── edit_generator.py               # 生成 Edit 操作
├── models.py                           # 数据模型
├── engine.py                           # 扫描引擎主入口
├── sast_patterns.py                    # 内置 SAST 模式库（降级用）
├── requirements.txt                    # 可选依赖
└── README.md                           # 文档
```

### 关键模块职责

| 模块 | 职责 |
|------|------|
| `engine.py` | 编排 Phase 1-5 的执行，提供统一 API |
| `scanners/project_probe.py` | 自动识别技术栈，确定加载哪些规则集 |
| `scanners/base.py` | 定义 `AbstractScanner` 接口，所有扫描器继承 |
| `scanners/config_scanner.py` | 加载 YAML 规则 → 匹配文件 → 生成 Finding |
| `scanners/sast_scanner.py` | 先用 semgrep/bandit，降级用 `sast_patterns.py` |
| `scanners/dependency_scanner.py` | 调用 pip-audit/npm audit 等，降级用内置缓存 |
| `scanners/business_scanner.py` | 分析代码结构中的认证、授权、支付逻辑 |
| `fixers/edit_generator.py` | 从 Finding 生成 `Edit` 操作，交互式执行 |
| `reporters/terminal.py` | 彩色 Markdown 表格输出 |
| `models.py` | `Finding`、`Fix`、`Report`、`Severity`、`ScanDimension` 等 |

### 核心数据模型

```python
# models.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanDimension(Enum):
    DEPENDENCY = "dependency"
    CONFIG = "config"
    SAST = "sast"
    AUTH = "auth"
    BUSINESS = "business"

@dataclass
class Finding:
    id: str                          # 唯一标识
    dimension: ScanDimension         # 扫描维度
    severity: Severity               # 严重度
    title: str                       # 标题
    description: str                 # 详细描述
    cwe: Optional[str] = None        # CWE 编号
    owasp: Optional[str] = None      # OWASP 分类
    file_path: Optional[str] = None  # 文件路径
    line: Optional[int] = None       # 行号
    code_snippet: Optional[str] = None  # 问题代码
    attack_scenario: Optional[str] = None  # 攻击场景
    fixes: list = field(default_factory=list)  # 修复方案列表

@dataclass
class Fix:
    description: str                 # 修复说明
    type: str                        # env_var / edit / config / architectural
    edit_operations: list = field(default_factory=list)  # Edit 操作
    effort: str = "medium"           # 工作量评估

@dataclass
class EditOperation:
    file: str                        # 文件路径
    old_string: str                  # 原字符串
    new_string: str                  # 新字符串

@dataclass
class Report:
    project_name: str                # 项目名称
    tech_stack: dict                 # 技术栈检测结果
    scan_time: float                 # 扫描耗时
    dimensions_covered: list         # 覆盖的维度
    findings: list                   # 所有发现
    total: int                       # 总计
    critical: int                    # 严重统计
    high: int
    medium: int
    low: int
    auto_fixable: int                # 可自动修复数量
```

---

## 附录 A：OWASP Top 10 (2021) 映射

| OWASP | 类别 | Agent 覆盖维度 |
|-------|------|---------------|
| A01: Broken Access Control | 访问控制缺陷 | Auth + Business |
| A02: Cryptographic Failures | 密码学失败 | Config + SAST |
| A03: Injection | 注入攻击 | SAST |
| A04: Insecure Design | 不安全设计 | Business |
| A05: Security Misconfiguration | 安全配置错误 | Config |
| A06: Vulnerable Components | 有漏洞的组件 | Dependency |
| A07: Auth Failures | 认证失败 | Auth + Business |
| A08: Data Integrity Failures | 数据完整性 | SAST + Business |
| A09: Logging & Monitoring | 日志与监控不足 | Config + Business |
| A10: SSRF | SSRF | SAST |

## 附录 B：CWE 参考

| CWE | 名称 | Agent 规则 |
|-----|------|-----------|
| CWE-79 | XSS | sast/xss |
| CWE-89 | SQL Injection | sast/sql-injection |
| CWE-94 | Code Injection | sast/command-injection |
| CWE-200 | Information Exposure | config/debug-mode |
| CWE-22 | Path Traversal | sast/path-traversal |
| CWE-352 | CSRF | django/csrf |
| CWE-798 | Hardcoded Credentials | base/secrets-in-code |
| CWE-918 | SSRF | sast/ssrf |
| CWE-502 | Deserialization | sast/unsafe-deserialization |
| CWE-915 | Prototype Pollution | js/prototype-pollution |

## 附录 C：术语表

| 术语 | 说明 |
|------|------|
| CVE | Common Vulnerabilities and Exposures，通用漏洞披露 |
| CVSS | Common Vulnerability Scoring System，通用漏洞评分系统 |
| CWE | Common Weakness Enumeration，通用弱点枚举 |
| SAST | Static Application Security Testing，静态应用安全测试 |
| IDOR | Insecure Direct Object Reference，不安全的直接对象引用 |
| SSRF | Server-Side Request Forgery，服务端请求伪造 |
| CSRF | Cross-Site Request Forgery，跨站请求伪造 |
| XSS | Cross-Site Scripting，跨站脚本攻击 |
| XXE | XML External Entity，XML 外部实体注入 |
| TOCTOU | Time-of-Check to Time-of-Use，检查时与使用时竞争条件 |
| OWASP | Open Web Application Security Project，开放 Web 应用安全项目 |
