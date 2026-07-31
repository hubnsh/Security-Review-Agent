"""
Python AST 安全扫描器 — 基于标准库 ast 模块。

相比 sast_patterns.py 的正则匹配，AST 扫描：
- 天然区分真实代码 vs 注释/字符串（无需正则启发式）
- 基础污点跟踪：检测用户输入是否流入危险函数
- 精确的行号定位
- 大幅降低误报率（无污染输入的危险调用不报 CRITICAL）

返回格式与 sast_patterns.match_in_content 兼容：
[{"vuln_type", "pattern", "description", "line", "match"}]
"""

import ast
from typing import Optional


# 危险调用目标
# mod: 模块名（"" = 任意模块 / 直接函数名）
# func: 函数名（None = 匹配 mod 下的任意方法，配合 any_attr）
# dynamic: eval/exec 类，任意非字面量参数都算风险
DANGEROUS_CALLS = [
    # ---- SQL 注入 ----
    {"mod": "", "func": "raw", "vuln": "sql-injection",
     "desc": "ORM raw() 原生 SQL 查询"},
    {"mod": "", "func": "extra", "vuln": "sql-injection",
     "desc": "ORM extra() 原生 SQL 查询"},
    {"mod": "cursor", "func": "execute", "vuln": "sql-injection",
     "desc": "cursor.execute() 未参数化"},
    {"mod": "connection", "func": "execute", "vuln": "sql-injection",
     "desc": "connection.execute() 未参数化"},
    # ---- 命令注入 ----
    {"mod": "os", "func": "system", "vuln": "command-injection",
     "desc": "os.system() 命令执行"},
    {"mod": "os", "func": "popen", "vuln": "command-injection",
     "desc": "os.popen() 命令执行"},
    {"mod": "subprocess", "func": None, "any_attr": True,
     "vuln": "command-injection", "desc": "subprocess 命令执行"},
    # ---- 反序列化 ----
    {"mod": "pickle", "func": "loads", "vuln": "unsafe-deserialization",
     "desc": "pickle.loads() 不安全反序列化"},
    {"mod": "yaml", "func": "load", "vuln": "unsafe-deserialization",
     "desc": "yaml.load() 未指定 SafeLoader"},
    {"mod": "shelve", "func": "open", "vuln": "unsafe-deserialization",
     "desc": "shelve.open() 使用 pickle"},
    # ---- 动态代码执行 ----
    {"mod": "", "func": "eval", "vuln": "eval-usage", "dynamic": True,
     "desc": "eval() 动态代码执行"},
    {"mod": "", "func": "exec", "vuln": "eval-usage", "dynamic": True,
     "desc": "exec() 动态代码执行"},
    {"mod": "", "func": "compile", "vuln": "eval-usage", "dynamic": True,
     "desc": "compile() 动态编译"},
    # ---- SSRF ----
    {"mod": "requests", "func": None, "any_attr": True,
     "vuln": "ssrf", "desc": "requests HTTP 请求"},
    {"mod": "urllib", "func": "urlopen", "vuln": "ssrf",
     "desc": "urllib.request.urlopen()"},
    {"mod": "", "func": "urlopen", "vuln": "ssrf",
     "desc": "urlopen() 请求"},
    # ---- 路径遍历 ----
    {"mod": "", "func": "send_file", "vuln": "path-traversal",
     "desc": "send_file() 文件发送"},
    {"mod": "os", "func": "open", "vuln": "path-traversal",
     "desc": "os.open() 文件打开"},
    # ---- XSS ----
    {"mod": "", "func": "mark_safe", "vuln": "xss",
     "desc": "mark_safe() 跳过转义"},
    # ---- 弱加密（与输入无关，只要使用即标记） ----
    {"mod": "hashlib", "func": "md5", "vuln": "weak-crypto",
     "desc": "hashlib.md5() 弱哈希", "always": True},
    {"mod": "hashlib", "func": "sha1", "vuln": "weak-crypto",
     "desc": "hashlib.sha1() 弱哈希", "always": True},
]

# 用户输入来源根变量（大小写不敏感前缀匹配）
SOURCE_ROOTS = {
    "request", "req", "body", "params", "query_params", "form",
    "form_data", "input_data", "data", "event", "kwargs",
    "files", "file", "path", "user_input", "user", "payload",
}


def _is_source_name(name: str) -> bool:
    """判断变量名是否疑似用户输入来源"""
    n = name.lower()
    return (
        n in SOURCE_ROOTS
        or n.startswith("request")
        or n.startswith("req_")
        or n.startswith("user_")
        or n == "body"
    )


def _expr_is_tainted(node: ast.AST, tainted: set[str]) -> bool:
    """判断表达式是否包含污染（用户输入）数据"""
    if isinstance(node, ast.Name):
        return _is_source_name(node.id) or node.id in tainted
    if isinstance(node, ast.Attribute):
        return _expr_is_tainted(node.value, tainted)
    if isinstance(node, ast.JoinedStr):
        return any(
            _expr_is_tainted(v.value, tainted)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp):
        return _expr_is_tainted(node.left, tainted) or _expr_is_tainted(
            node.right, tainted
        )
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            return _expr_is_tainted(func.value, tainted)
        if isinstance(func, ast.Name) and _is_source_name(func.id):
            return True
        return False
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_expr_is_tainted(e, tainted) for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(
            _expr_is_tainted(k, tainted) or _expr_is_tainted(v, tainted)
            for k, v in zip(node.keys or [], node.values)
        )
    return False


def _expr_is_dynamic(node: ast.AST) -> bool:
    """判断表达式是否为动态内容（eval/exec 场景）"""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.Name):
        return node.id != "_"
    return True


def _call_target(node: ast.Call) -> tuple[Optional[str], Optional[str]]:
    """提取调用目标 (模块名, 函数名)"""
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return func.value.id, func.attr
        if isinstance(func.value, ast.Attribute):
            return None, func.attr
        return None, func.attr
    if isinstance(func, ast.Name):
        return "", func.id
    return None, None


def scan_python_source(content: str) -> list[dict]:
    """
    扫描一段 Python 源码，返回安全发现列表。

    Args:
        content: Python 源码文本

    Returns:
        List of {"vuln_type", "pattern", "description", "line", "match"}
    """
    results = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return results

    tainted: set[str] = set()

    for node in ast.walk(tree):
        # 污点传播：赋值
        if isinstance(node, ast.Assign):
            value_tainted = _expr_is_tainted(node.value, tainted)
            for target in node.targets:
                if isinstance(target, ast.Name) and value_tainted:
                    tainted.add(target.id)
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.value is not None
                and _expr_is_tainted(node.value, tainted)
            ):
                tainted.add(node.target.id)
        elif isinstance(node, ast.AugAssign):
            if (
                isinstance(node.target, ast.Name)
                and _expr_is_tainted(node.value, tainted)
            ):
                tainted.add(node.target.id)

        if not isinstance(node, ast.Call):
            continue

        mod, func = _call_target(node)
        if func is None:
            continue

        for spec in DANGEROUS_CALLS:
            # 匹配目标
            if spec["func"] is None and spec.get("any_attr"):
                matched = bool(mod) and spec["mod"] in mod and bool(func)
            elif spec["func"] is not None:
                matched = func == spec["func"] and (
                    spec["mod"] == "" or mod == spec["mod"]
                )
            else:
                matched = False

            if not matched:
                continue

            # 风险判定
            if spec.get("always"):
                # 与输入无关：只要使用即标记（如弱哈希）
                risky = True
            elif spec.get("dynamic"):
                # eval/exec: 非字面量参数即风险
                risky = any(_expr_is_dynamic(a) for a in node.args)
            else:
                risky = any(
                    _expr_is_tainted(a, tainted) for a in node.args
                ) or any(
                    _expr_is_tainted(kw.value, tainted)
                    for kw in node.keywords
                )

            if not risky:
                continue

            try:
                snippet = ast.unparse(node)[:100]
            except (AttributeError, TypeError):
                snippet = f"{mod}.{func}" if mod else func

            results.append({
                "vuln_type": spec["vuln"],
                "pattern": f"AST:{mod}.{func}" if mod else f"AST:{func}",
                "description": spec["desc"],
                "line": node.lineno,
                "match": snippet,
            })
            break  # 一条调用只报一次

    return results
