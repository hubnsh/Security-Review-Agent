"""
Security Review Agent — 通用工具函数

包含：文件操作、YAML 规则加载匹配、项目探针、版本对比等
"""

import os
import re
import fnmatch
from pathlib import Path
from typing import Optional


# =====================================================================
# 文件工具
# =====================================================================

def read_file_content(file_path: str, max_bytes: int = 1_048_576) -> Optional[str]:
    """
    读取文件内容，如果文件过大或无法读取则返回 None。

    Args:
        file_path: 文件路径
        max_bytes: 最大读取字节数（默认 1MB）

    Returns:
        文件内容字符串，或 None（读取失败）
    """
    try:
        size = os.path.getsize(file_path)
        if size > max_bytes:
            return None
        # 尝试多种编码
        for encoding in ["utf-8", "gbk", "latin-1", "utf-16"]:
            try:
                with open(file_path, "r", encoding=encoding, errors="replace") as f:
                    return f.read()
            except (UnicodeDecodeError, UnicodeError):
                continue
        return None
    except (OSError, FileNotFoundError):
        return None


def glob_files(root_dir: str, pattern: str) -> list[str]:
    """
    使用 glob 模式匹配文件。兼容 Windows/Linux。

    Args:
        root_dir: 根目录
        pattern: glob 模式（如 "**/*.py"）

    Returns:
        匹配的文件路径列表
    """
    from glob import iglob
    full_pattern = os.path.join(root_dir, pattern)
    return list(iglob(full_pattern, recursive=True))


PYTHON_INDICATORS = {
    "files": ["**/*.py"],
    "configs": ["**/requirements.txt", "**/pyproject.toml", "**/setup.py", "**/Pipfile"],
    "frameworks": {
        "django": ["**/settings.py", "**/wsgi.py", "**/manage.py"],
        "flask": ["**/app.py"],
        "fastapi": ["**/main.py"],
    },
}

JAVASCRIPT_INDICATORS = {
    "files": ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"],
    "configs": ["**/package.json", "**/yarn.lock", "**/pnpm-lock.yaml"],
    "frameworks": {
        "express": ["**/app.js", "**/server.js", "**/express"],
        "react": ["**/App.jsx", "**/App.tsx", "**/react"],
        "vue": ["**/vue.config.js", "**/nuxt.config"],
        "nest": ["**/nest-cli.json"],
    },
}


def detect_language(file_count: dict[str, int]) -> list[str]:
    """根据文件后缀统计检测语言"""
    ext_map = {
        ".py": "python",
        ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".go": "go",
        ".java": "java", ".kt": "kotlin",
        ".rb": "ruby",
        ".rs": "rust",
        ".php": "php",
        ".cs": "csharp",
        ".swift": "swift",
        ".c": "c", ".h": "c",
        ".cpp": "cpp", ".hpp": "cpp",
    }

    languages = set()
    for ext, lang in ext_map.items():
        if file_count.get(ext, 0) > 0:
            languages.add(lang)
    return sorted(languages)


def is_text_file(file_path: str) -> bool:
    """判断文件是否为文本文件（非二进制）"""
    text_extensions = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb",
        ".rs", ".php", ".cs", ".swift", ".c", ".h", ".cpp", ".hpp",
        ".kt", ".scala", ".swift",
        ".md", ".rst", ".txt", ".ini", ".cfg", ".conf",
        ".yml", ".yaml", ".json", ".xml", ".html", ".htm", ".css",
        ".scss", ".less", ".vue", ".svelte",
        ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
        ".env", ".env.example",
        ".gitignore", ".dockerignore", ".editorconfig",
        ".sql", ".graphql", ".proto",
        ".toml", ".ini", ".cfg",
    }
    ext = Path(file_path).suffix.lower()
    return ext in text_extensions


def should_exclude_path(file_path: str) -> bool:
    """检查路径是否应被排除（node_modules/、venv/、.git/ 等）"""
    exclude_patterns = [
        "**/node_modules/**",
        "**/venv/**",
        "**/.git/**",
        "**/__pycache__/**",
        "**/.next/**",
        "**/dist/**",
        "**/build/**",
        "**/.cache/**",
        "**/target/**",
        "**/vendor/**",
        "**/.tox/**",
        "**/env/**",
        "**/.env/**",
        "**/site-packages/**",
        "**/bower_components/**",
    ]
    normalized = file_path.replace("\\", "/")
    for pattern in exclude_patterns:
        norm_pattern = pattern.replace("\\", "/")
        if fnmatch.fnmatch(normalized, norm_pattern):
            return True
    return False


# =====================================================================
# 规则加载/匹配工具
# =====================================================================

def parse_yaml_rule(yaml_content: str) -> Optional[dict]:
    """
    解析 YAML 规则内容（纯字符串解析，不依赖 PyYAML 库）。
    返回 dict 或 None（解析失败）。
    注意：此方法仅支持简单的 YAML 语法。
    """
    # 尝试用标准库解析
    try:
        import yaml as pyyaml
        return pyyaml.safe_load(yaml_content)
    except ImportError:
        pass

    # 简易解析器（仅用于简单 YAML）
    result = {}
    current_key = None
    current_list = None

    for line in yaml_content.split("\n"):
        stripped = line.strip()

        # 跳过注释和空行
        if not stripped or stripped.startswith("#"):
            continue

        # 检测键值对
        if ":" in stripped and not stripped.startswith("-"):
            parts = stripped.split(":", 1)
            key = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else None

            # 去掉引号
            if value and len(value) >= 2 and value[0] in ("'", '"') and value[0] == value[-1]:
                value = value[1:-1]

            if value == "" or value is None:
                current_key = key
                result[current_key] = []
            elif value.startswith("[") and value.endswith("]"):
                # 内联列表
                items = [v.strip().strip("'\"") for v in value[1:-1].split(",") if v.strip()]
                result[key] = items
            else:
                result[key] = value
                current_key = key

        # 列表项
        elif stripped.startswith("- ") and current_key:
            item_value = stripped[2:].strip()
            if item_value.startswith("{") and item_value.endswith("}"):
                # 内联字典，跳过（需要完整 YAML 解析器）
                pass
            else:
                if isinstance(result.get(current_key), list):
                    result[current_key].append(item_value.strip("'\""))

    return result if result else None


def match_rule_condition(condition: dict, file_content: Optional[str]) -> bool:
    """
    检测文件内容是否满足规则条件。

    Args:
        condition: 条件定义 (dict)，包含 type 和参数
        file_content: 文件内容，None 表示文件不存在

    Returns:
        True 表示条件匹配
    """
    if file_content is None:
        return False

    ctype = condition.get("type", "")
    pattern = condition.get("pattern", "")

    try:
        if ctype == "file_contains":
            return pattern in file_content
        elif ctype == "file_not_contains":
            return pattern not in file_content
        elif ctype == "line_matches":
            return bool(re.search(pattern, file_content, re.MULTILINE))
        elif ctype == "line_not_matches":
            return not bool(re.search(pattern, file_content, re.MULTILINE))
        elif ctype == "regex_in_file":
            flags_raw = condition.get("flags", 0)
            flags = 0
            if isinstance(flags_raw, int):
                flags = flags_raw
            return bool(re.search(pattern, file_content, flags | re.MULTILINE))
        elif ctype == "file_exists":
            return True  # 文件存在且已被读取
        elif ctype == "value_equals":
            # 简单配置值匹配
            return bool(re.search(
                rf"{re.escape(condition['key'])}\s*[=:]\s*{re.escape(condition['value'])}",
                file_content
            ))
    except re.error:
        pass

    return False


def compute_git_diff(ref: str, root_path: str) -> list[str]:
    """
    计算与指定 Git ref 相比有变更的文件列表。

    git diff 从子目录运行时会输出仓库根相对路径（如 "sub/dir/file.py"），
    因此先通过 rev-parse 获取仓库根，再把路径拼接到仓库根上。

    Args:
        ref: Git ref (如 "HEAD~1", "origin/main")
        root_path: 项目根目录（可以是仓库内任意子目录）

    Returns:
        变更文件的绝对路径列表
    """
    import subprocess
    try:
        # 获取仓库根目录
        root_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, cwd=root_path,
            timeout=30,
        )
        if root_result.returncode != 0:
            return []
        repo_root = root_result.stdout.strip()

        result = subprocess.run(
            ["git", "diff", ref, "--name-only"],
            capture_output=True, text=True, cwd=root_path,
            timeout=30,
        )
        if result.returncode != 0:
            return []
        files = [f.strip() for f in result.stdout.split("\n") if f.strip()]
        # 仓库根相对路径 → 绝对路径
        return [os.path.abspath(os.path.join(repo_root, f)) for f in files]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


# =====================================================================
# 假阳性管理 (.secreview-ignore)
# =====================================================================

# .secreview-ignore 文件格式:
#
#   每行一条忽略规则，支持三种格式：
#   1. 精确路径+行号+规则:   src/main.py:42:django-csrf-disabled
#   2. 路径通配+规则:        src/models/*:sast-sql-injection
#   3. 全局规则忽略:         :::sast-hardcoded-credentials
#   4. 注释行:               # 这是注释
#   5. 空行跳过


def load_ignore_rules(ignore_file_path: str) -> list[dict]:
    """
    加载 .secreview-ignore 忽略规则文件。

    Args:
        ignore_file_path: 忽略文件路径

    Returns:
        List of {"file_pattern": str, "line": int|None,
                 "rule_pattern": str, "raw": str}
    """
    rules = []
    try:
        with open(ignore_file_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # 解析 file:line:rule 格式
                parts = stripped.split(":", 2)
                file_pattern = parts[0].strip() if len(parts) > 0 else ""
                line_str = parts[1].strip() if len(parts) > 1 else ""
                raw_rule = parts[2].strip() if len(parts) > 2 else ""

                # 处理 src/models/*:::sast-sql-injection 的情况
                # 空 line 字段导致 rule 带前导冒号
                if raw_rule.startswith(":"):
                    raw_rule = raw_rule[1:]

                line_num = None
                if line_str and line_str.isdigit():
                    line_num = int(line_str)

                rules.append({
                    "file_pattern": file_pattern or "*",
                    "line": line_num,
                    "rule_pattern": raw_rule or "*",
                    "raw": stripped,
                })
    except (FileNotFoundError, PermissionError):
        pass

    return rules


def is_ignored(file_path: str, line: int, rule_id: str,
               ignore_rules: list[dict]) -> bool:
    """
    检查某个 Finding 是否匹配忽略规则。

    Args:
        file_path: 文件路径（相对于项目根）
        line: 行号
        rule_id: 规则 ID
        ignore_rules: 从 load_ignore_rules() 加载的规则列表

    Returns:
        True 表示应忽略
    """
    import fnmatch

    for rule in ignore_rules:
        fp = rule.get("file_pattern", "*")
        rp = rule.get("rule_pattern", "*")
        rl = rule.get("line")

        # 文件匹配
        if not fnmatch.fnmatch(file_path.replace("\\", "/"), fp):
            continue

        # 规则 ID 匹配
        if not fnmatch.fnmatch(rule_id, rp):
            continue

        # 行号匹配（如果指定了行号）
        if rl is not None and rl != line:
            continue

        return True

    return False


def generate_fix_operations(rule: dict, file_path: str, original_content: str) -> list[dict]:
    """
    根据规则的 fix 定义生成 EditOperation。

    Args:
        rule: 解析后的规则 dict
        file_path: 目标文件路径
        original_content: 文件原始内容

    Returns:
        List of {"file", "old_string", "new_string", "description"}
    """
    operations = []
    fixes = rule.get("fix", [])

    for fix_def in fixes:
        fix_type = fix_def.get("type", "")
        description = fix_def.get("description", "")

        if fix_type == "edit" or fix_type == "uncomment":
            search = fix_def.get("search") or fix_def.get("old")
            replacement = fix_def.get("replacement") or fix_def.get("new")

            if not search or not replacement:
                continue

            # 如果 search 是正则，找第一个匹配行
            try:
                match = re.search(search, original_content, re.MULTILINE)
                if match:
                    operations.append({
                        "file": file_path,
                        "old_string": original_content[match.start():match.end()],
                        "new_string": replacement,
                        "description": description,
                    })
            except re.error:
                # 普通字符串匹配
                if search in original_content:
                    operations.append({
                        "file": file_path,
                        "old_string": search,
                        "new_string": replacement,
                        "description": description,
                    })

    return operations
