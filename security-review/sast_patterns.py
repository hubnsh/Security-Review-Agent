"""
SAST 模式库 — 内置正则模式匹配规则

当 bandit / semgrep 等外部工具不可用时，使用此模块进行静态代码分析。

结构：SAST_PATTERNS[漏洞类型][语言] = [(regex, description), ...]
"""

SAST_PATTERNS = {
    # =====================================================================
    # SQL 注入
    # =====================================================================
    "sql-injection": {
        "python": [
            (r'\.raw\(\s*f["\']', "Django raw query with f-string (SQLi risk)"),
            (r"\.extra\(\s*.*where\s*=.*[\"']\s*\+",
             "Django extra() with string concatenation (SQLi)"),
            (r"cursor\.execute\(\s*f[\"']",
             "Raw cursor execute with f-string (SQLi)"),
            (r"execute\([\"'].*\%[\(s%d]",
             "SQL execute with % formatting (SQLi risk)"),
            (r"\.execute\([\"']SELECT.*\+",
             "SQL execute with string concatenation"),
            (r"connection\.execute\(\s*f[\"']",
             "Database connection execute with f-string (SQLi)"),
        ],
        "javascript": [
            (r"db\.\w+\.\$where\(\s*[\"']\s*\+",
             "MongoDB $where with concatenation (NoSQLi)"),
            (r"SELECT.*\+(?:req\.|res\.|body\.|query\.)",
             "SQL concatenation with request data"),
            (r"sequelize\.query\(\s*[\"'].*\+",
             "Sequelize raw query with concatenation"),
        ],
        "java": [
            (r"Statement\.executeQuery\(\s*[\"']",
             "Raw Statement usage (use PreparedStatement)"),
            (r"\+\s*request\.getParameter",
             "SQL concatenation with request parameter"),
            (r"Statement\.execute\(\s*[\"'].*\+",
             "SQL execute with string concatenation"),
        ],
        "ruby": [
            (r"where\(\s*[\"'].*#\{",
             "ActiveRecord where with string interpolation (SQLi)"),
            (r"execute\(\s*[\"'].*\+",
             "SQL execute with string concatenation"),
            (r"find_by_sql\(\s*[\"'].*\+",
             "find_by_sql with string concatenation"),
        ],
        "go": [
            (r"db\.(Query|Exec|QueryRow)\(\s*f[\"']",
             "database/sql raw query with f-string (SQLi)"),
            (r"\.Raw\(\s*f[\"']",
             "GORM raw query with f-string (SQLi)"),
            (r"\.Exec\(\s*f[\"']",
             "GORM Exec with f-string (SQLi)"),
            (r"fmt\.Sprintf\([\"'].*(?:SELECT|INSERT|UPDATE|DELETE)",
             "fmt.Sprintf building SQL (SQLi)"),
        ],
        "csharp": [
            (r"\+\s*request\[",
             "ASP.NET request parameter in string concatenation"),
            (r"ExecuteQuery\(\s*[\"'].*\+",
             "LINQ ExecuteQuery with concatenation"),
        ],
        "php": [
            (r"mysqli_query\(\s*[\"'].*\$",
             "mysqli_query with variable interpolation (SQLi)"),
            (r"query\(\s*[\"'].*\$",
             "PDO query with variable interpolation (SQLi)"),
            (r"\$wpdb->query\(\s*[\"'].*\$",
             "WordPress $wpdb->query with variable (SQLi)"),
            (r"\$wpdb->get_results\(\s*[\"'].*\$",
             "WordPress $wpdb->get_results with variable (SQLi)"),
        ],
        "kotlin": [
            (r"Squery\s*\(", "Exposed SQL query building (potential SQLi)"),
            (r"rawQuery\s*\(", "Android rawQuery (SQLi)"),
            (r"execSQL\s*\(", "Android execSQL (SQLi)"),
        ],
    },

    # =====================================================================
    # 命令注入
    # =====================================================================
    "command-injection": {
        "python": [
            (r"os\.system\(\s*f[\"']",
             "Command injection via f-string in os.system()"),
            (r"os\.popen\(\s*f[\"']",
             "Command injection via f-string in os.popen()"),
            (r"subprocess\.[a-zA-Z]+\(\s*f[\"']",
             "Command injection via f-string in subprocess"),
            (r"subprocess\.[a-zA-Z]+\([\"'].*\+.*(?:request|input|param|user|data)",
             "Subprocess with user input concatenation"),
            (r"eval\(\s*[\"']",
             "eval() with dynamic code"),
        ],
        "javascript": [
            (r"exec\(\s*f[\"']",
             "Command injection via f-string in exec()"),
            (r"exec\(\s*[\"'].*\+.*(?:req\.|body\.|query\.)",
             "exec() with user input concatenation"),
            (r"spawn\(\s*[\"'].*\+",
             "spawn() with string concatenation (use shell=false)"),
            (r"execSync\(\s*[\"'].*\+",
             "execSync() with user input"),
        ],
        "go": [
            (r"exec\.Command\(\s*[\"'].*\+",
             "exec.Command with string concatenation"),
            (r"exec\.CommandContext\(\s*[\"'].*\+",
             "exec.CommandContext with string concat"),
            (r"os\.StartProcess\(",
             "os.StartProcess with potential injection"),
        ],
        "java": [
            (r"Runtime\.getRuntime\(\)\.exec\(\s*[\"'].*\+",
             "Runtime.exec with string concatenation"),
            (r"ProcessBuilder\([\"'].*\+",
             "ProcessBuilder with string concatenation"),
        ],
        "ruby": [
            (r"`\s*[\"'].*#\{",
             "Backtick shell execution with interpolation"),
            (r"system\(\s*[\"'].*\+",
             "Kernel#system with string concatenation"),
            (r"exec\(\s*[\"'].*\+",
             "Kernel#exec with string concatenation"),
        ],
        "csharp": [
            (r"Process\.Start\(\s*[\"'].*\+",
             "Process.Start with string concatenation"),
        ],
        "php": [
            (r"exec\(\s*[\"'].*\$", "exec() with variable (command injection)"),
            (r"system\(\s*[\"'].*\$", "system() with variable (command injection)"),
            (r"shell_exec\(\s*[\"'].*\$", "shell_exec() with variable (command injection)"),
            (r"passthru\(\s*[\"'].*\$", "passthru() with variable (command injection)"),
            (r"`\s*\$", "Backtick execution with variable (command injection)"),
        ],
    },

    # =====================================================================
    # 路径遍历
    # =====================================================================
    "path-traversal": {
        "python": [
            (r"open\(\s*os\.path\.join\([^)]*,\s*(?:request|user|input|filepath|filename)",
             "Path traversal: user input in file path"),
            (r"open\(\s*f[\"'].*\{.*(?:request|user|input)",
             "Path traversal: f-string in file path with user input"),
            (r"send_file\(\s*(?:request|user|input|filepath|filename)",
             "Path traversal: user input in send_file()"),
        ],
        "javascript": [
            (r"res\.sendFile\(\s*(?:req\.|body\.|query\.)",
             "Path traversal risk in sendFile()"),
            (r"fs\.(readFile|readFileSync)\(\s*(?:req\.|body\.|query\.)",
             "Path traversal in fs.readFile()"),
            (r"fs\.(writeFile|writeFileSync)\(\s*(?:req\.|body\.|query\.)",
             "Path traversal in fs.writeFile()"),
            (r"fs\.(unlink|unlinkSync|rm|rmSync)\(\s*(?:req\.|body\.|query\.)",
             "Path traversal in fs deletion"),
        ],
        "go": [
            (r"os\.(Open|ReadFile|WriteFile|Create)\(\s*(?:req|r\.|c\.)",
             "Path traversal in Go file operations"),
            (r"ioutil\.(ReadFile|WriteFile|ReadDir)\(\s*(?:req|r\.|c\.)",
             "Path traversal in ioutil operations"),
            (r"http\.(ServeFile|FileServer|ServeContent)\(",
             "Path traversal in Go HTTP file serving"),
        ],
        "java": [
            (r"new File\(.*request\.getParameter",
             "Path traversal: File with request parameter"),
            (r"FileInputStream\(.*request\.getParameter",
             "Path traversal: FileInputStream with request param"),
            (r"File\.(createNewFile|delete|renameTo)\(",
             "File operations in Java"),
        ],
    },

    # =====================================================================
    # XSS（跨站脚本）
    # =====================================================================
    "xss": {
        "python": [
            (r"mark_safe\(", "mark_safe() used without input escaping (XSS)"),
            (r"\{\{.*\|safe\}\}", "Django template 'safe' filter bypasses escaping (XSS)"),
            (r"HttpResponse\(.*(?:request|input|user)",
             "HttpResponse with user input without escaping"),
        ],
        "javascript": [
            (r"dangerouslySetInnerHTML\s*=",
             "dangerouslySetInnerHTML bypasses React's XSS protection"),
            (r"\.innerHTML\s*=.*(?:req\.|body\.|query\.|params\.)",
             "innerHTML assignment with user input (XSS)"),
            (r"v-html\s*=", "Vue v-html directive renders raw HTML (XSS)"),
            (r"document\.write\(.*(?:req\.|body\.|query\.)",
             "document.write() with user input"),
        ],
        "go": [
            (r"template\.(HTML|HTMLEscapeString)\(",
             "Go template HTML escaping bypass"),
            (r"template\.Must\(.*\.Parse\(.*user",
             "User input in Go template parsing"),
        ],
        "java": [
            (r"write\(.*request\.getParameter",
             "JSP writing user input without escaping (XSS)"),
            (r"out\.print\(.*request\.getParameter",
             "JSP out.print with request parameter (XSS)"),
        ],
    },

    # =====================================================================
    # 不安全反序列化
    # =====================================================================
    "unsafe-deserialization": {
        "python": [
            (r"pickle\.loads?\s*\(", "Unsafe pickle deserialization (RCE risk)"),
            (r"yaml\.load\(\s*(?!.*Loader=(?:SafeLoader|FullLoader|CLoader))",
             "Unsafe yaml.load() without SafeLoader (RCE risk)"),
            (r"shelve\.open\(",
             "shelve.open() uses pickle internally (RCE risk)"),
        ],
        "javascript": [
            (r"JSON\.parse\(\s*(?:req\.|body\.|query\.)",
             "JSON.parse() without schema validation"),
        ],
        "java": [
            (r"ObjectInputStream\.readObject\s*\(",
             "Unsafe Java deserialization (RCE risk)"),
            (r"readResolve\(", "Custom readResolve (potential deserialization)"),
        ],
    },

    # =====================================================================
    # SSRF（服务端请求伪造）
    # =====================================================================
    "ssrf": {
        "python": [
            (r"requests\.(get|post|put|delete|patch)\(\s*(?:request|body|query|input|url)",
             "User-controlled URL in HTTP request (SSRF)"),
            (r"urllib\.request\.urlopen\(\s*(?:request|body|query|input|url)",
             "User-controlled URL in urllib (SSRF)"),
        ],
        "javascript": [
            (r"fetch\(\s*(?:req\.|body\.|query\.)",
             "User-controlled URL in fetch() (SSRF)"),
            (r"axios\.(get|post|put|delete)\(\s*(?:req\.|body\.|query\.)",
             "User-controlled URL in axios (SSRF)"),
            (r"got\(\s*(?:req\.|body\.|query\.)",
             "User-controlled URL in got (SSRF)"),
        ],
        "go": [
            (r"net/http\.(Get|Post|Head|Do)\(\s*(?:req|r\.|c\.)",
             "User-controlled URL in Go HTTP client (SSRF)"),
            (r"http\.NewRequest\(\s*[\"'](?:GET|POST).*req",
             "User-controlled URL in Go NewRequest (SSRF)"),
        ],
        "java": [
            (r"URL\(.*request\.getParameter",
             "User-controlled URL in Java URL (SSRF)"),
            (r"openConnection\(\).*request",
             "User-controlled URL in Java URLConnection (SSRF)"),
            (r"RestTemplate\.(get|post|exchange)\(.*request",
             "User-controlled URL in RestTemplate (SSRF)"),
        ],
        "ruby": [
            (r"open\(\s*params\[",
             "User-controlled URL in open() (SSRF)"),
            (r"Net::HTTP\.(get|post)\(.*params",
             "User-controlled URL in Net::HTTP (SSRF)"),
            (r"HTTParty\.(get|post)\(.*params",
             "User-controlled URL in HTTParty (SSRF)"),
        ],
    },

    # =====================================================================
    # eval 动态代码执行
    # =====================================================================
    "eval-usage": {
        "python": [
            (r"eval\(\s*[\"']", "eval() with dynamic code (code injection)"),
            (r"exec\(\s*[\"']", "exec() with dynamic code (code injection)"),
            (r"compile\(\s*[\"']", "compile() with dynamic code"),
        ],
        "javascript": [
            (r"eval\(\s*[\"']", "eval() usage (code injection risk)"),
            (r"new Function\(\s*[\"']",
             "new Function() is equivalent to eval (code injection)"),
            (r"setTimeout\(\s*[\"'].*\+",
             "setTimeout with string argument (eval-like)"),
        ],
    },

    # =====================================================================
    # 硬编码凭据
    # =====================================================================
    "hardcoded-credentials": {
        "python": [
            (r"(password|passwd|pwd)\s*=\s*[\"'][^\"']{8,}[\"']",
             "Hardcoded password in source code"),
        ],
        "all": [
            (r"(SECRET_[A-Z_]+)\s*[=:]\s*[\"'][^\"' ]+[\"']",
             "Hardcoded SECRET_* value"),
            (r"(API[_-]?KEY)\s*[=:]\s*[\"'][^\"' ]+[\"']",
             "Hardcoded API key"),
            (r"(TOKEN)\s*[=:]\s*[\"'][^\"' ]{8,}[\"']",
             "Hardcoded token"),
        ],
    },

    # =====================================================================
    # XXE（XML 外部实体注入）
    # =====================================================================
    "xxe": {
        "python": [
            (r"xml\.etree\.ElementTree\.(parse|fromstring)\s*\(",
             "XML parsing without entity protection (XXE)"),
            (r"lxml\.(parse|fromstring)\s*\(",
             "lxml parsing without entity protection (XXE)"),
            (r"xml\.dom\.(parse|parseString)\s*\(",
             "XML DOM parsing (XXE risk)"),
            (r"xml\.sax\.(parse|parseString)\s*\(",
             "XML SAX parsing (XXE risk)"),
        ],
        "java": [
            (r"DocumentBuilder\.parse\s*\(",
             "XML parsing without XXE protection"),
            (r"SAXParser\.parse\s*\(",
             "SAX parsing without XXE protection"),
            (r"XMLInputFactory\.createXMLStreamReader",
             "XML stream reader without XXE protection"),
        ],
    },

    # =====================================================================
    # 原型污染 (JavaScript)
    # =====================================================================
    "prototype-pollution": {
        "javascript": [
            (r"Object\.assign\(\s*\{", "Object.assign with empty target (prototype pollution)"),
            (r"_.merge\(\s*\{", "lodash _.merge with empty target"),
            (r"\.__proto__\s*=", "Direct __proto__ assignment"),
            (r"\.constructor\.prototype\s*=", "Direct constructor.prototype assignment"),
        ],
    },

    # =====================================================================
    # 不安全的随机数 (Insecure Random)
    # =====================================================================
    "insecure-random": {
        "javascript": [
            (r"Math\.random\s*\(",
             "Math.random() is not cryptographically secure — verify it's not used for tokens/keys"),
        ],
        "python": [
            (r"import\s+random\b",
             "Python 'random' module is not cryptographically secure — use secrets module"),
            (r"random\.random\s*\(\s*\).*token|token.*random\.random",
             "random.random() used near token generation (should use secrets.token_*)"),
        ],
        "java": [
            (r"new\s+Random\s*\(\)\s*.*(?:password|token|salt|secret)",
             "java.util.Random is not cryptographically secure — use SecureRandom"),
            (r"Math\.random\s*\(\s*\).*(?:password|token|salt|secret)",
             "Math.random() used in security context — use SecureRandom"),
        ],
    },

    # =====================================================================
    # 弱 TLS/HTTPS 配置
    # =====================================================================
    "weak-tls": {
        "python": [
            (r"verify\s*=\s*False", "SSL verification disabled"),
            (r"cert_reqs\s*=\s*ssl\.CERT_NONE", "SSL certificate validation disabled"),
            (r"check_hostname\s*=\s*False", "SSL hostname checking disabled"),
        ],
        "javascript": [
            (r"process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]",
             "TLS certificate validation disabled"),
            (r"rejectUnauthorized\s*:\s*false",
             "TLS rejectUnauthorized disabled"),
        ],
    },
}


def get_patterns_for_language(vuln_type: str, language: str) -> list:
    """
    获取指定语言在指定漏洞类型下的所有模式。

    Args:
        vuln_type: 漏洞类型 (e.g., "sql-injection", "xss")
        language: 语言名 (e.g., "python", "javascript")

    Returns:
        List of (regex, description) tuples
    """
    patterns = []
    vuln = SAST_PATTERNS.get(vuln_type, {})

    # 语言特定模式
    if language in vuln:
        patterns.extend(vuln[language])

    # "all" 语言模式（适用于所有语言）
    if "all" in vuln:
        patterns.extend(vuln["all"])

    return patterns


def get_all_vuln_types() -> list[str]:
    """获取所有支持的漏洞类型列表"""
    return list(SAST_PATTERNS.keys())


def _strip_line_comments(line: str, language: str) -> str:
    """
    去除行中的注释部分，返回空白填充的字符串以保持行号对齐。

    Args:
        line: 单行代码
        language: 语言名

    Returns:
        注释被替换为等长空格的字符串
    """
    if language == "python":
        # Python: # 注释
        idx = _find_unquoted(line, "#")
        if idx >= 0:
            return line[:idx] + " " * (len(line) - idx)
    elif language in ("javascript", "typescript", "go", "java", "csharp", "php", "rust"):
        # 先处理 // 注释
        idx = _find_unquoted(line, "//")
        if idx >= 0:
            return line[:idx] + " " * (len(line) - idx)
    elif language == "ruby":
        idx = _find_unquoted(line, "#")
        if idx >= 0:
            return line[:idx] + " " * (len(line) - idx)
    elif language in ("c", "cpp", "swift", "kotlin"):
        idx = _find_unquoted(line, "//")
        if idx >= 0:
            return line[:idx] + " " * (len(line) - idx)
    return line


def _find_unquoted(line: str, marker: str) -> int:
    """
    在字符串中查找不在引号内的标记。

    Args:
        line: 代码行
        marker: 要查找的标记（如 "#" 或 "//"）

    Returns:
        标记位置，-1 表示未找到或全在引号内
    """
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double and (i == 0 or line[i - 1] != '\\'):
            in_single = not in_single
        elif ch == '"' and not in_single and (i == 0 or line[i - 1] != '\\'):
            in_double = not in_double
        elif not in_single and not in_double:
            if line[i:].startswith(marker):
                return i
        i += 1
    return -1


def _strip_block_comments(content: str, language: str) -> str:
    """
    去除块级注释（如 /* ... */）。

    Args:
        content: 文件内容
        language: 语言名

    Returns:
        块注释被替换为等长空格的字符串
    """
    languages_with_block_comments = {
        "javascript", "typescript", "go", "java", "csharp",
        "php", "rust", "c", "cpp", "swift", "kotlin", "ruby",
    }
    if language not in languages_with_block_comments:
        return content

    result = list(content)
    i = 0
    while i < len(content) - 1:
        # 不在引号内时才检查
        if content[i] == '/' and content[i + 1] == '*':
            # 确认不在引号内
            prefix = content[:i]
            if prefix.count('"') % 2 == 0 and prefix.count("'") % 2 == 0:
                end = content.find("*/", i + 2)
                if end >= 0:
                    for j in range(i, end + 2):
                        if content[j] not in ('\n', '\r'):
                            result[j] = ' '
                    i = end + 2
                    continue
        i += 1
    return ''.join(result)


def match_in_content(content: str, language: str) -> list[dict]:
    """
    对一段代码内容执行所有 SAST 模式匹配。

    预处理：
    1. 去除块级注释（/* ... */）
    2. 按行去除行注释（# 或 //）

    Args:
        content: 文件内容
        language: 语言名

    Returns:
        List of {"vuln_type", "pattern", "description", "line"} dicts
    """
    import re
    results = []

    # 预处理：去除块级注释
    clean_content = _strip_block_comments(content, language)

    for vuln_type in SAST_PATTERNS:
        patterns = get_patterns_for_language(vuln_type, language)
        for regex, description in patterns:
            for match in re.finditer(regex, clean_content):
                # 计算行号
                line_num = content[:match.start()].count('\n') + 1

                # 获取匹配所在的原始行内容
                lines = content.split('\n')
                orig_line = lines[line_num - 1] if line_num - 1 < len(lines) else ""

                # 进一步检查该行是否在注释中
                cleaned_line = _strip_line_comments(orig_line, language).strip()
                if not cleaned_line:
                    continue  # 匹配在注释中，跳过

                # 检查匹配位置是否在去注释后仍然有效
                clean_lines = clean_content.split('\n')
                clean_line = clean_lines[line_num - 1] if line_num - 1 < len(clean_lines) else ""
                if match.group() not in clean_line:
                    continue  # 匹配在注释中，跳过

                results.append({
                    "vuln_type": vuln_type,
                    "pattern": regex,
                    "description": description,
                    "line": line_num,
                    "match": match.group()[:100],  # 截断过长匹配
                })

    return results
