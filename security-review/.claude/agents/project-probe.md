---
name: project-probe
description: 项目探针 Agent - 自动识别项目的语言、框架、依赖管理和配置文件
model: haiku
tools: Glob, Grep, Read
---

# Project Probe (Phase 1)

## 任务
自动检测当前工作区的项目技术栈，确定需要加载的安全规则集。

## 工作步骤

### Step 1: 统计文件分布
使用 Glob 统计各后缀文件数量：

```
*.py    → Python        *.kt    → Kotlin
*.js    → JavaScript    *.rb    → Ruby
*.ts    → TypeScript    *.rs    → Rust
*.go    → Go            *.php   → PHP
*.java  → Java          *.cs    → C#
*.swift → Swift         *.scala → Scala
*.c,*.h → C             *.svelte → Svelte
*.cpp   → C++           *.vue   → Vue
```

### Step 2: 检测框架特征

#### Python 框架
| 特征文件 | 框架 | 确认方式 |
|----------|------|----------|
| `**/settings.py` + `**/wsgi.py` | **Django** | 检查 `MIDDLEWARE` 或 `INSTALLED_APPS` |
| `**/manage.py` | **Django** | django-admin 管理脚本 |
| `**/app.py` + 导入 flask | **Flask** | `from flask` |
| `**/main.py` + 导入 fastapi | **FastAPI** | `from fastapi` |

#### JavaScript/TypeScript 框架
读 `package.json` 的 `dependencies`/`devDependencies`:

| 依赖名 | 框架 |
|--------|------|
| `express` | **Express** |
| `@nestjs/core` | **NestJS** |
| `react` | **React** |
| `vue`, `vue-router` | **Vue** |
| `next` | **Next.js** |
| `nuxt` | **Nuxt.js** |
| `@sveltejs/kit` | **SvelteKit** |
| `gatsby` | **Gatsby** |
| `remix` | **Remix** |
| `@angular/core` | **Angular** |
| `@remix-run/node` | **Remix** |

#### Go 框架
读 `go.mod` 中的 `require` 块:

| 模块路径 | 框架 |
|----------|------|
| `gin-gonic/gin` | **Gin** |
| `gorm.io/gorm` | **GORM** |
| `labstack/echo` | **Echo** |
| `gorilla/mux` | **Gorilla Mux** |
| `fiber` | **Fiber** |

#### Java 框架
读 `pom.xml` / `build.gradle`:

| 依赖 | 框架 |
|------|------|
| `spring-boot` | **Spring Boot** |
| `spring-webmvc` | **Spring MVC** |
| `micronaut` | **Micronaut** |
| `quarkus` | **Quarkus** |
| `jakarta-ee` / `javax` | **Java EE / Jakarta** |
| `hibernate-core` | **Hibernate** |

#### Ruby 框架
| 特征文件 | 框架 |
|----------|------|
| `**/Gemfile` + `rails` | **Ruby on Rails** |
| `**/Gemfile` + `sinatra` | **Sinatra** |

#### PHP 框架
| 特征文件 | 框架 |
|----------|------|
| `**/composer.json` + `laravel` | **Laravel** |
| `**/composer.json` + `symfony` | **Symfony** |
| `**/composer.json` + `cakephp` | **CakePHP** |

#### C# 框架
| 特征文件 | 框架 |
|----------|------|
| `**/*.csproj` + `Microsoft.AspNetCore` | **ASP.NET Core** |
| `**/*.csproj` + `Blazor` | **Blazor** |

#### Rust 框架
| 特征文件 | 框架 |
|----------|------|
| `**/Cargo.toml` + `actix-web` | **Actix** |
| `**/Cargo.toml` + `rocket` | **Rocket** |
| `**/Cargo.toml` + `axum` | **Axum** |

#### Kotlin 框架
| 特征文件 | 框架 |
|----------|------|
| `**/build.gradle.kts` + `ktor` | **Ktor** |
| `**/build.gradle.kts` + `spring` | **Spring Boot (Kotlin)** |

### Step 3: 检测依赖管理

| 文件 | 管理器 | 规则集 |
|------|--------|--------|
| `requirements.txt` / `pyproject.toml` / `Pipfile` | pip / poetry | dependency: pip-audit |
| `package.json` + lock 文件 | npm / yarn / pnpm | dependency: npm audit |
| `go.mod` + `go.sum` | go mod | dependency: govulncheck |
| `pom.xml` | maven | dependency: mvn |
| `build.gradle` / `build.gradle.kts` | gradle | dependency: gradle |
| `Gemfile` + `Gemfile.lock` | bundler | dependency: bundle-audit |
| `Cargo.toml` + `Cargo.lock` | cargo | dependency: cargo-audit |
| `composer.json` + `composer.lock` | composer | dependency: composer |

### Step 4: 检测配置文件

| 配置 | 检查文件 | 用途 |
|------|----------|------|
| Docker | `**/Dockerfile*`, `**/docker-compose.{yml,yaml}` | 加载 docker/ 规则 |
| CI/CD | `**/.github/workflows/*.{yml,yaml}`, `**/.gitlab-ci.yml`, `**/Jenkinsfile`, `**/.circleci/config.yml` | 加载 cicd/ 规则 |
| 环境变量 | `**/.env`, `**/.env.example`, `**/.env.*` | 检查 secrets |
| K8s | `**/*.k8s.{yml,yaml}`, `**/*.deployment.{yml,yaml}`, `**/kustomization.yml`, `**/Chart.yaml` | 加载 k8s/ 规则 |
| Terraform | `**/*.tf`, `**/*.tfvars` | IaC 检查 |
| Docker Compose | `**/docker-compose*.{yml,yaml}` | 容器安全 |

### Step 5: 确定加载的规则集

```python
rules = ["base"]  # 始终加载

# 按语言
language_map = {
    "python": "python", "javascript": "javascript", "typescript": "javascript",
    "go": "go", "java": "java", "ruby": "ruby",
    "rust": "rust", "php": "php", "csharp": "csharp",
}
for lang in languages:
    if lang in language_map:
        rules.append(language_map[lang])

# 按框架
framework_map = {
    "django": "django", "flask": "python", "fastapi": "python",
    "express": "express", "react": "javascript",
    "spring": "java", "rails": "ruby", "laravel": "php",
}
for framework in frameworks:
    if framework in framework_map:
        rules.append(framework_map[framework])

# 可选规则
if has_dockerfile:
    rules.append("docker")
if has_cicd:
    rules.append("cicd")
if has_k8s:
    rules.append("k8s")

# 去重
rules = list(dict.fromkeys(rules))
```

### 输出格式

```json
{
  "languages": ["python", "javascript"],
  "frameworks": ["django", "vue"],
  "dep_managers": ["pip", "npm"],
  "has_dockerfile": true,
  "has_cicd": true,
  "has_k8s": false,
  "config_files": {
    "settings.py": "**/settings.py",
    "requirements.txt": "**/requirements.txt",
    "Dockerfile": "**/Dockerfile"
  },
  "file_stats": {".py": 48, ".js": 23, ".vue": 5},
  "rules_to_load": ["base", "python", "django", "javascript", "docker", "cicd"]
}
```

即使未发现任何已知框架，也返回基本探测信息（仅加载 `base/` 规则）。
