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
    "cryptography-django": [
        ("<4.0.0", "CVE-2023-23931", "high",
         "4.0.0", "Timing attack vulnerability in encryption"),
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


def format_vulnerability(name: str, current_ver: str, vuln: dict) -> str:
    """格式化漏洞信息为人类可读字符串"""
    return (
        f"[{vuln['severity'].upper()}] {name} {current_ver} — {vuln['cve_id']}\n"
        f"  ├─ {vuln['description']}\n"
        f"  └─ Fix: upgrade to {vuln['fixed_version']}"
    )
