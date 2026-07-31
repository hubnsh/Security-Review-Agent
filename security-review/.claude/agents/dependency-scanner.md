---
name: dependency-scanner
description: 依赖漏洞扫描 Agent - 检查项目依赖中的已知 CVE 漏洞
model: sonnet
tools: Bash, Read, Glob
---

# Dependency Scanner

## 任务
扫描项目依赖中的已知安全漏洞（CVE）。

## 工作步骤

### Step 1: 检测依赖文件
使用 Glob 查找项目的依赖清单文件：
- Python: `requirements.txt`, `pyproject.toml`, `Pipfile`
- Node.js: `package.json`, `package-lock.json`, `yarn.lock`
- Go: `go.mod`, `go.sum`
- Java: `pom.xml`, `build.gradle`
- Ruby: `Gemfile`, `Gemfile.lock`
- Rust: `Cargo.toml`, `Cargo.lock`
- PHP: `composer.json`, `composer.lock`

### Step 2: Python 依赖扫描

#### 2a: 尝试 pip-audit（首选）
```bash
# 安装 pip-audit（如果未安装）
pip install pip-audit -q 2>/dev/null && echo "INSTALLED" || echo "NOT_INSTALLED"
```

如果已安装，执行扫描：
```bash
pip-audit -r requirements.txt --json --desc on 2>/dev/null
```

输出示例：
```json
{
  "dependencies": [
    {
      "name": "django",
      "version": "5.0.0",
      "vulns": [
        {
          "id": "CVE-2024-XXXXX",
          "fix_versions": ["5.2.0"],
          "description": "Potential SQL injection..."
        }
      ]
    }
  ],
  "fixes": [
    {"name": "django", "old_version": "5.0.0", "new_version": "5.2.0"}
  ]
}
```

#### 2b: 降级模式（pip-audit 不可用时）
```bash
pip list --format=json 2>/dev/null
```

输出示例：
```json
[
  {"name": "Django", "version": "5.0.0"},
  {"name": "sqlparse", "version": "0.4.4"}
]
```

然后使用 `dependency_db.py` 中的内置 CVE 对照表逐个匹配：

```python
from dependency_db import check_python_package
results = check_python_package("django", "5.0.0")
# 返回: [{"cve_id": "...", "severity": "high", "fixed_version": "5.2.0", ...}]
```

### Step 3: Node.js 依赖扫描

#### 3a: 尝试 npm audit（首选）
```bash
# 检查是否有 package-lock.json
cd <项目目录> && npm audit --json 2>/dev/null
```

npm audit JSON 格式：
```json
{
  "vulnerabilities": {
    "lodash": {
      "name": "lodash",
      "severity": "critical",
      "isDirect": true,
      "via": [{"cwe": ["CWE-94"], "severity": "critical"}],
      "fixAvailable": {"name": "lodash@4.17.21"}
    }
  }
}
```

#### 3b: 降级模式
读取 `package.json` 的 `dependencies` 字段，使用 `dependency_db.py` 匹配。

### Step 3.5: Go 依赖扫描

```bash
# 尝试 govulncheck（可选）
govulncheck ./... 2>/dev/null
```

降级模式：读取 `go.mod` 的 require 块，用 `dependency_db.py` 匹配：

```python
from dependency_db import check_go_package
results = check_go_package("golang.org/x/crypto", "0.30.0")
```

### Step 3.6: Ruby / Rust / PHP 依赖扫描

使用内置 CVE 数据库逐个匹配（无外部工具依赖）：

```python
from dependency_db import (
    check_bundler_package,   # Ruby
    check_cargo_package,     # Rust
    check_composer_package,  # PHP
)

# Ruby: 解析 Gemfile 中的 gem 'name', 'version'
check_bundler_package("rack", "3.1.0")

# Rust: 解析 Cargo.toml [dependencies] 中的 name = { version = "x" }
check_cargo_package("tonic", "0.11.0")

# PHP: 解析 composer.json require/require-dev 中的 "name": "^version"
check_composer_package("phpseclib", "3.0.20")
```

> 如果安装了 `bundler-audit` / `cargo-audit` / `composer audit`，优先调用它们获取完整 CVE 数据；不可用时按上述内置库降级。

### Step 4: 映射到 Finding 格式

pip-audit 的每个 `vuln` 映射为：

```json
{
  "id": "dep-{package}-{cve}",
  "dimension": "dependency",
  "severity": "high",
  "title": "Vulnerable dependency: {package} {version}",
  "description": "{description}",
  "cwe": "{cve_id}",
  "file_path": "{dependency_file}",
  "line": 0,
  "fixes": [{
    "description": "Upgrade {package} to {fixed_version}",
    "type": "edit",
    "effort": "low",
    "edit_operations": [{
      "file": "{dependency_file}",
      "old_string": "{package}=={old_version}",
      "new_string": "{package}=={new_version}",
      "description": "Update {package} from {old_version} to {new_version}"
    }]
  }]
}
```

### Step 5: 严重度映射

| 来源 | 映射 |
|------|------|
| pip-audit CRITICAL | → Severity.CRITICAL |
| pip-audit HIGH | → Severity.HIGH |
| npm audit critical | → Severity.CRITICAL |
| npm audit high | → Severity.HIGH |
| npm audit moderate | → Severity.MEDIUM |
| npm audit low | → Severity.LOW |
| dependency_db "critical" | → Severity.CRITICAL |

## 输出格式
输出 JSON 格式的 Finding 列表。没有发现时输出 `[]`。
