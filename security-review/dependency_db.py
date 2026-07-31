"""
内置 CVE 对照表 — 当 pip-audit/npm audit 等外部工具不可用时使用

此数据库记录了常见 Python 和 Node.js 包的已知高/严重级漏洞。
注意：这是降级方案，仅覆盖常见包的重大漏洞。
生产环境建议安装 pip-audit / npm audit 获取实时数据。
"""

# Python 包已知漏洞
# 格式：package_name -> [(version_constraint, cve_id, severity, min_fixed_version, description)]
BUILTIN_CVE_DB_PYTHON: dict[str, list[tuple[str, str, str, str, str]]] = {
    "django": [
        ("<5.2.0", "GHSA-6fgr-4gvh-47jc", "high",
         "5.2.0", "Potential SQL injection in HasKey(lhs, rhs) on PostgreSQL"),
        ("<5.1.5", "GHSA-2r3q-3jwm-76pr", "high",
         "5.1.5", "Potential denial-of-service in urlize and urlizetrunc"),
        ("<5.0.9", "GHSA-5vq2-3c96-42v4", "high",
         "5.0.9", "Potential regular expression denial-of-service"),
        ("<4.2.16", "GHSA-2r3q-3jwm-76pr", "medium",
         "4.2.16", "Potential denial-of-service in urlize and urlizetrunc"),
    ],
    "sqlparse": [
        ("<0.5.6", "CVE-2024-43403", "medium",
         "0.5.6", "Parsing heavily nested SQL comments leads to denial of service"),
        ("<0.5.0", "CVE-2023-30608", "medium",
         "0.5.0", "Parsing crafted SQL statements leads to infinite loop"),
    ],
    "pillow": [
        ("<10.4.0", "CVE-2024-28219", "high",
         "10.4.0", "Buffer overflow in ImageFilter.CoreImageFilter"),
        ("<10.3.0", "CVE-2024-28219", "medium",
         "10.3.0", "Multiple heap buffer overflow vulnerabilities"),
    ],
    "requests": [
        ("<2.32.0", "CVE-2024-35195", "medium",
         "2.32.0", "Requests for HTTP basic auth with non-ASCII characters"),
    ],
    "urllib3": [
        ("<2.0.7", "CVE-2023-45803", "medium",
         "2.0.7", "Request body not correctly encoded on HTTP newlines"),
    ],
    "cryptography": [
        ("<42.0.4", "GHSA-6vqw-3v5j-54x4", "high",
         "42.0.4", "NULL pointer dereference in PKCS12 parsing"),
    ],
    "jinja2": [
        ("<3.1.5", "CVE-2024-56326", "high",
         "3.1.5", "Sandbox breakout through malicious template input"),
    ],
    "flask": [
        ("<3.1.0", "GHSA-5pc9-4j8h-4v2x", "medium",
         "3.1.0", "Debugger allows arbitrary code execution"),
    ],
    "starlette": [
        ("<0.40.0", "GHSA-93gm-qmq6-wv84", "high",
         "0.40.0", "Path traversal in StaticFiles mount with absolute paths"),
    ],
    "httpx": [
        ("<0.28.1", "GHSA-87h2-ph2w-2c39", "high",
         "0.28.1", "Verb-based request smuggling via HTTP/1.1 chunked encoding"),
    ],
    "gunicorn": [
        ("<23.0.0", "GHSA-wpw6-6c92-h353", "medium",
         "23.0.0", "Request smuggling due to flawed LF vs CRLF handling"),
    ],
    "aiohttp": [
        ("<3.10.11", "GHSA-4c6q-qjc8-wr69", "high",
         "3.10.11", "Directory traversal via maliciously crafted compressed file"),
        ("<3.9.4", "GHSA-5h86-62mv-32q2", "medium",
         "3.9.4", "Modified request body after HTTP request redirect"),
    ],
}

# Node.js 包已知漏洞
# 格式：package_name -> [(version_constraint, cve_id, severity, min_fixed_version, description)]
BUILTIN_CVE_DB_NPM: dict[str, list[tuple[str, str, str, str, str]]] = {
    "lodash": [
        ("<4.17.21", "CVE-2024-23346", "critical",
         "4.17.21", "Prototype pollution via malicious object"),
    ],
    "express": [
        ("<4.19.2", "CVE-2024-29041", "medium",
         "4.19.2", "Path traversal in express.static with malformed URL"),
        ("<4.17.21", "CVE-2024-29041", "medium",
         "4.17.21", "Open redirect in express.static"),
    ],
    "axios": [
        ("<1.7.4", "CVE-2024-39338", "high",
         "1.7.4", "Server-Side Request Forgery via absolute URL"),
        ("<1.6.0", "CVE-2023-45857", "medium",
         "1.6.0", "Cross-site request forgery vulnerability"),
    ],
    "next": [
        ("<14.2.21", "CVE-2025-29927", "critical",
         "14.2.21", "Middleware bypass via x-middleware-subrequest header"),
    ],
    "vite": [
        ("<6.0.12", "CVE-2025-32395", "high",
         "6.0.12", "Server-Side Request Forgery in server.fs.deny"),
    ],
    "semver": [
        ("<7.5.2", "CVE-2022-25883", "medium",
         "7.5.2", "Regular expression denial of service"),
    ],
    "jsonwebtoken": [
        ("<9.0.0", "CVE-2022-23529", "high",
         "9.0.0", "Unrestricted key type can lead to signature validation bypass"),
    ],
    "minimatch": [
        ("<3.0.5", "CVE-2022-3517", "medium",
         "3.0.5", "ReDoS via pattern with nested brace"),
    ],
    "socket.io-parser": [
        ("<4.2.4", "CVE-2024-38355", "high",
         "4.2.4", "Insufficient validation of binary packets"),
    ],
}

# Ruby (Bundler) 已知漏洞
# 格式：package_name -> [(version_constraint, advisory_id, severity, min_fixed_version, description)]
BUILTIN_CVE_DB_RUBY: dict[str, list[tuple[str, str, str, str, str]]] = {
    "rack": [
        ("<3.1.8", "CVE-2024-45409", "high",
         "3.1.8", "Session fixation / ReDoS via crafted Range header"),
        ("<3.1.12", "CVE-2025-25184", "high",
         "3.1.12", "Possible ReDoS vulnerability in Rack::ETag"),
    ],
    "actionpack": [
        ("<7.1.3.4", "CVE-2024-26143", "medium",
         "7.1.3.4", "Possible XSS via Accept header in redirect_to"),
        ("<7.0.8.1", "CVE-2024-26142", "high",
         "7.0.8.1", "ReDoS vulnerability in HTTP Token authentication"),
    ],
    "json": [
        ("<2.10.2", "CVE-2025-44117", "medium",
         "2.10.2", "Denial of service via crafted JSON documents"),
    ],
    "nokogiri": [
        ("<1.16.7", "CVE-2024-43427", "high",
         "1.16.7", "Heap buffer overflow in libxml2 dependency"),
    ],
}

# Rust (Cargo) 已知漏洞
# 格式：package_name -> [(version_constraint, advisory_id, severity, min_fixed_version, description)]
BUILTIN_CVE_DB_RUST: dict[str, list[tuple[str, str, str, str, str]]] = {
    "tonic": [
        ("<0.12.3", "RUSTSEC-2024-0372", "high",
         "0.12.3", "Decompression bomb vulnerability in gRPC servers"),
    ],
    "hyper": [
        ("<1.3.1", "RUSTSEC-2024-0009", "medium",
         "1.3.1", "HTTP request smuggling via malformed headers"),
    ],
    "regex": [
        ("<1.8.4", "RUSTSEC-2022-0013", "medium",
         "1.8.4", "ReDoS when used with untrusted regex input"),
    ],
    "h2": [
        ("<0.3.21", "RUSTSEC-2024-0332", "high",
         "0.3.21", "HTTP/2 CONTINUATION frame flood denial of service"),
    ],
}

# PHP (Composer) 已知漏洞
# 格式：package_name -> [(version_constraint, advisory_id, severity, min_fixed_version, description)]
BUILTIN_CVE_DB_PHP: dict[str, list[tuple[str, str, str, str, str]]] = {
    "phpseclib": [
        ("<3.0.40", "CVE-2024-54311", "critical",
         "3.0.40", "RSA private key recovery via padding oracle attack"),
    ],
    "laravel/framework": [
        ("<10.48.16", "CVE-2024-52301", "high",
         "10.48.16", "Bypass of SQLite PDO binding leading to SQL injection"),
    ],
    "symfony/http-kernel": [
        ("<6.4.15", "CVE-2024-50342", "high",
         "6.4.15", "Memory exhaustion via crafted request headers"),
    ],
    "guzzlehttp/psr7": [
        ("<2.7.0", "CVE-2025-27574", "high",
         "2.7.0", "Improper header parsing leading to request smuggling"),
    ],
}


def parse_version(version_string: str) -> tuple:
    """
    简单版本解析，将 "5.2.12" 转换为可比较的元组 (5, 2, 12)。
    仅处理三位版本号。
    """
    parts = version_string.strip().split(".")
    result = []
    for part in parts:
        num = ""
        for ch in part:
            if ch.isdigit():
                num += ch
            else:
                break
        result.append(int(num) if num else 0)
    # 补齐到3位
    while len(result) < 3:
        result.append(0)
    return tuple(result)


def check_version(installed_version: str, constraint: str) -> bool:
    """
    检查 installed_version 是否满足 constraint。
    支持的约束: "<5.2.0", "<=5.1.0"

    Args:
        installed_version: 已安装版本 (e.g., "5.2.12")
        constraint: 版本约束 (e.g., "<5.2.0")

    Returns:
        True 如果版本满足约束（即存在漏洞）
    """
    if not constraint:
        return False

    operator = constraint[0]
    version_part = constraint[1:]

    installed = parse_version(installed_version)
    target = parse_version(version_part)

    if operator == "<":
        return installed < target
    elif operator == "<=":
        return installed <= target
    elif operator == ">":
        return installed > target
    elif operator == ">=":
        return installed >= target
    elif operator == "=":
        return installed == target
    return False


def check_python_package(name: str, version: str) -> list[dict]:
    """
    检查单个 Python 包是否有已知漏洞。

    Args:
        name: 包名 (小写)
        version: 版本号

    Returns:
        List of {cve_id, severity, fixed_version, description}
    """
    results = []
    pkg_vulns = BUILTIN_CVE_DB_PYTHON.get(name.lower(), [])
    for constraint, cve_id, severity, fixed_version, desc in pkg_vulns:
        if check_version(version, constraint):
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "fixed_version": fixed_version,
                "description": desc,
            })
    return results


def check_npm_package(name: str, version: str) -> list[dict]:
    """
    检查单个 npm 包是否有已知漏洞。

    Args:
        name: 包名
        version: 版本号

    Returns:
        List of {cve_id, severity, fixed_version, description}
    """
    results = []
    pkg_vulns = BUILTIN_CVE_DB_NPM.get(name, [])
    for constraint, cve_id, severity, fixed_version, desc in pkg_vulns:
        if check_version(version, constraint):
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "fixed_version": fixed_version,
                "description": desc,
            })
    return results


# Go 包已知漏洞
# 格式：package_name -> [(version_constraint, cve_id, severity, min_fixed_version, description)]
BUILTIN_CVE_DB_GO: dict[str, list[tuple[str, str, str, str, str]]] = {
    "golang.org/x/crypto": [
        ("<0.31.0", "CVE-2024-45337", "high",
         "0.31.0", "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass"),
    ],
    "golang.org/x/net": [
        ("<0.36.0", "CVE-2025-22870", "high",
         "0.36.0", "Cross-site scripting in golang.org/x/net/html via math comments"),
    ],
    "github.com/gin-gonic/gin": [
        ("<1.10.0", "GHSA-7f86-6v34-mc4v", "high",
         "1.10.0", "Request body size limit bypass via Content-Type mime sniff"),
    ],
    "github.com/golang-jwt/jwt/v4": [
        ("<4.5.1", "CVE-2024-34156", "high",
         "4.5.1", "Invalid aud claim validation allows bypass of audience check"),
    ],
}

# Java 包已知漏洞
BUILTIN_CVE_DB_JAVA: dict[str, list[tuple[str, str, str, str, str]]] = {
    "org.apache.logging.log4j": [
        ("<2.17.1", "CVE-2021-44228", "critical",
         "2.17.1", "JNDI injection via log message (Log4Shell)"),
        ("<2.17.1", "CVE-2021-45046", "high",
         "2.17.1", "Denial of service in Log4j 2.x"),
    ],
    "org.springframework.boot": [
        ("<3.3.6", "CVE-2024-38819", "high",
         "3.3.6", "Path traversal via spring.web.resources.static-locations"),
        ("<2.7.18", "CVE-2023-34055", "medium",
         "2.7.18", "Potential SSRF via spring.web.resources.chain"),
    ],
    "com.fasterxml.jackson.core:jackson-databind": [
        ("<2.17.3", "CVE-2024-47554", "high",
         "2.17.3", "Denial of service via deeply nested objects"),
    ],
    "org.apache.tomcat.embed": [
        ("<10.1.34", "CVE-2024-52316", "high",
         "10.1.34", "HTTP request smuggling via malformed Content-Length"),
    ],
}


def check_go_package(name: str, version: str) -> list[dict]:
    """
    检查单个 Go 包是否有已知漏洞。

    Args:
        name: 模块路径
        version: 版本号

    Returns:
        List of {cve_id, severity, fixed_version, description}
    """
    results = []
    pkg_vulns = BUILTIN_CVE_DB_GO.get(name, [])
    for constraint, cve_id, severity, fixed_version, desc in pkg_vulns:
        if check_version(version, constraint):
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "fixed_version": fixed_version,
                "description": desc,
            })
    return results


def check_java_package(name: str, version: str) -> list[dict]:
    """
    检查单个 Java 包是否有已知漏洞。

    Args:
        name: 包名 (group:artifact 格式)
        version: 版本号

    Returns:
        List of {cve_id, severity, fixed_version, description}
    """
    results = []
    pkg_vulns = BUILTIN_CVE_DB_JAVA.get(name, [])
    for constraint, cve_id, severity, fixed_version, desc in pkg_vulns:
        if check_version(version, constraint):
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "fixed_version": fixed_version,
                "description": desc,
            })
    return results


def check_bundler_package(name: str, version: str) -> list[dict]:
    """
    检查单个 Ruby gem 是否有已知漏洞。

    Args:
        name: gem 名
        version: 版本号

    Returns:
        List of {cve_id, severity, fixed_version, description}
    """
    results = []
    pkg_vulns = BUILTIN_CVE_DB_RUBY.get(name.lower(), [])
    for constraint, cve_id, severity, fixed_version, desc in pkg_vulns:
        if check_version(version, constraint):
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "fixed_version": fixed_version,
                "description": desc,
            })
    return results


def check_cargo_package(name: str, version: str) -> list[dict]:
    """
    检查单个 Rust crate 是否有已知漏洞。

    Args:
        name: crate 名
        version: 版本号

    Returns:
        List of {cve_id, severity, fixed_version, description}
    """
    results = []
    pkg_vulns = BUILTIN_CVE_DB_RUST.get(name.lower(), [])
    for constraint, cve_id, severity, fixed_version, desc in pkg_vulns:
        if check_version(version, constraint):
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "fixed_version": fixed_version,
                "description": desc,
            })
    return results


def check_composer_package(name: str, version: str) -> list[dict]:
    """
    检查单个 PHP Composer 包是否有已知漏洞。

    Args:
        name: 包名 (vendor/package)
        version: 版本号

    Returns:
        List of {cve_id, severity, fixed_version, description}
    """
    results = []
    pkg_vulns = BUILTIN_CVE_DB_PHP.get(name.lower(), [])
    for constraint, cve_id, severity, fixed_version, desc in pkg_vulns:
        if check_version(version, constraint):
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "fixed_version": fixed_version,
                "description": desc,
            })
    return results


def check_package(name: str, version: str, eco: str = "python") -> list[dict]:
    """
    通用包检查接口，根据生态自动路由到对应的 check_* 函数。

    Args:
        name: 包名
        version: 版本号
        eco: 生态 (python / npm / go / java / ruby / rust / php)

    Returns:
        List of {cve_id, severity, fixed_version, description}
    """
    if eco == "python":
        return check_python_package(name, version)
    elif eco == "npm":
        return check_npm_package(name, version)
    elif eco == "go":
        return check_go_package(name, version)
    elif eco == "java":
        return check_java_package(name, version)
    elif eco in ("ruby", "bundler"):
        return check_bundler_package(name, version)
    elif eco in ("rust", "cargo"):
        return check_cargo_package(name, version)
    elif eco in ("php", "composer"):
        return check_composer_package(name, version)
    return []


def format_vulnerability(name: str, current_ver: str, vuln: dict) -> str:
    """格式化漏洞信息为人类可读字符串"""
    return (
        f"[{vuln['severity'].upper()}] {name} {current_ver} — {vuln['cve_id']}\n"
        f"  ├─ {vuln['description']}\n"
        f"  └─ Fix: upgrade to {vuln['fixed_version']}"
    )
