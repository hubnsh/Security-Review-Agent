#!/usr/bin/env python3
"""
Security Review Agent — 独立 CLI 入口

用法:
    python engine.py                              # 全量扫描
    python engine.py --quick                      # 快速扫描（配置 + 依赖）
    python engine.py --focus config               # 仅配置扫描
    python engine.py --focus sast                 # 仅 SAST 扫描
    python engine.py --output json                # JSON 输出
    python engine.py --output markdown            # Markdown 输出
    python engine.py --diff HEAD~1                # 增量扫描（Git 变更）
    python engine.py --apply all                  # 自动应用全部修复
    python engine.py --apply 1,3,5                # 应用指定编号修复
    python engine.py --no-fix                     # 不生成修复方案
    python engine.py --path /path/to/project      # 指定项目路径

CI 模式:
    python engine.py --output json --no-fix       # CI 流水线集成

环境变量:
    SECREVIEW_IGNORE_PATH: 自定义忽略文件路径（默认 .secreview-ignore）
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Windows GBK 终端兼容输出
def _safe_print(text: str, **kwargs):
    """安全输出，自动处理编码问题"""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        sanitized = text.encode("ascii", errors="replace").decode("ascii")
        print(sanitized, **kwargs)

from models import (
    Severity, ScanDimension, Finding, Fix, EditOperation,
    Report, ProbeResult,
)
from utils import (
    read_file_content, glob_files, detect_language,
    is_text_file, should_exclude_path, match_rule_condition,
    generate_fix_operations, parse_yaml_rule, load_ignore_rules,
    is_ignored as utils_is_ignored, compute_git_diff,
    clear_glob_cache,
)
from dependency_db import (
    check_python_package, check_npm_package,
    check_go_package, check_java_package,
    format_vulnerability,
)
from sast_patterns import match_in_content, get_all_vuln_types
from ast_scanner import scan_python_source


# =====================================================================
# 内置忽略规则默认路径
# =====================================================================
IGNORE_FILE = ".secreview-ignore"

# 审计日志文件（企业级：每次扫描/修复的操作痕迹）
# 可用环境变量 SECREVIEW_AUDIT_LOG 指定路径
AUDIT_LOG_DEFAULT = os.environ.get(
    "SECREVIEW_AUDIT_LOG",
    os.path.join(os.getcwd(), "security-audit.log.jsonl"),
)

ENGINE_VERSION = "2.2.0"


def _get_git_commit(root_path: str) -> str:
    """获取当前 git 提交哈希（便于审计复现）"""
    import subprocess
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=root_path, timeout=10,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _get_rules_version(rules_dir: str) -> str:
    """计算规则集版本（文件数 + 最新修改时间哈希）"""
    import hashlib
    files = sorted(glob_files(rules_dir, "**/*.yml"))
    if not files:
        return "0"
    h = hashlib.md5()
    for f in files:
        h.update(os.path.basename(f).encode("utf-8"))
    return f"{len(files)}-{h.hexdigest()[:8]}"


def _log_audit(event: str, details: dict, audit_path: str = "") -> None:
    """
    写审计日志（JSON Lines 格式）。

    Args:
        event: 事件类型（scan_start / scan_complete / fix_applied / fix_skipped）
        details: 事件详情（自动附加时间戳）
        audit_path: 日志文件路径（默认 AUDIT_LOG_DEFAULT）
    """
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "event": event,
        "engine_version": ENGINE_VERSION,
        **details,
    }
    try:
        path = audit_path or AUDIT_LOG_DEFAULT
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


# 外部工具开关（由 --no-external 控制）
USE_EXTERNAL_TOOLS = True


# =====================================================================
# YAML 规则校验（--validate-rules）
# =====================================================================

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_DETECT_TYPES = {
    "file_contains", "file_not_contains", "line_matches",
    "line_not_matches", "regex_in_file", "file_exists", "value_equals",
}
VALID_FIX_TYPES = {
    "edit", "uncomment", "insert", "insert_after", "insert_before",
    "config", "replace_with_env_var", "add_to_gitignore",
}


def validate_rule(rule: dict, file_path: str) -> list[str]:
    """
    校验单条规则的结构，返回错误列表（空 = 通过）。

    不依赖 jsonschema 库，实现核心约束检查。
    """
    errors = []
    rpath = os.path.basename(file_path)

    if not rule.get("id"):
        errors.append(f"{rpath}: 缺少必填字段 'id'")
    if not rule.get("name"):
        errors.append(f"{rpath}: 缺少必填字段 'name'")

    sev = rule.get("severity")
    if sev not in VALID_SEVERITIES:
        errors.append(f"{rpath}: severity '{sev}' 非法（应为 {sorted(VALID_SEVERITIES)}）")

    for i, cond in enumerate(rule.get("detect", [])):
        if not isinstance(cond, dict):
            errors.append(f"{rpath}: detect[{i}] 不是对象")
            continue
        ctype = cond.get("type")
        if ctype not in VALID_DETECT_TYPES:
            errors.append(
                f"{rpath}: detect[{i}].type '{ctype}' 非法"
            )
        # regex/line 类条件必须有 pattern
        if ctype in ("regex_in_file", "line_matches", "line_not_matches",
                     "file_contains", "file_not_contains"):
            if not cond.get("pattern"):
                errors.append(f"{rpath}: detect[{i}].pattern 缺失")
        if ctype == "value_equals":
            if not cond.get("key") or not cond.get("value"):
                errors.append(f"{rpath}: detect[{i}].key/value 缺失")

    for i, fix in enumerate(rule.get("fix", [])):
        if not isinstance(fix, dict):
            errors.append(f"{rpath}: fix[{i}] 不是对象")
            continue
        ftype = fix.get("type")
        if ftype not in VALID_FIX_TYPES:
            errors.append(f"{rpath}: fix[{i}].type '{ftype}' 非法")
        effort = fix.get("effort")
        if effort and effort not in ("low", "medium", "high"):
            errors.append(f"{rpath}: fix[{i}].effort '{effort}' 非法")

    return errors


def validate_all_rules(rules_dir: str) -> tuple[int, int]:
    """
    校验所有 YAML 规则文件。

    Returns:
        (规则总数, 出错数)
    """
    count = 0
    error_count = 0
    for yml in glob_files(rules_dir, "**/*.yml"):
        content = read_file_content(yml)
        if not content:
            continue
        rule = parse_yaml_rule(content)
        if not rule:
            _safe_print(f"⚠️  无法解析: {yml}", file=sys.stderr)
            error_count += 1
            count += 1
            continue
        errors = validate_rule(rule, yml)
        count += 1
        if errors:
            error_count += 1
            for e in errors:
                _safe_print(f"❌ {e}", file=sys.stderr)
        else:
            _safe_print(f"✅ {os.path.relpath(yml, rules_dir)}")
    return count, error_count


# =====================================================================
# 外部工具调用（pip-audit / bandit）— 可选，缺失时自动降级
# =====================================================================

def _run_tool(cmd: list[str], cwd: str, timeout: int = 180):
    """
    运行外部工具命令，成功返回 stdout，失败返回 None。

    Args:
        cmd: 命令列表
        cwd: 工作目录
        timeout: 超时秒数

    Returns:
        (stdout, returncode) 或 None（工具不存在/超时）
    """
    import subprocess
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout,
        )
        return result.stdout, result.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _try_pip_audit(requirements_file: str, root_path: str) -> Optional[list[Finding]]:
    """
    尝试用 pip-audit 扫描 requirements.txt。

    成功返回 Finding 列表；工具不可用或失败返回 None（调用方降级）。
    """
    if not USE_EXTERNAL_TOOLS:
        return None

    stdout = _run_tool(
        ["pip-audit", "-r", requirements_file, "--json", "--desc", "on"],
        root_path,
    )
    if stdout is None or stdout[1] != 0:
        return None

    try:
        data = json.loads(stdout[0])
    except (json.JSONDecodeError, TypeError):
        return None

    findings = []
    rel_path = os.path.relpath(requirements_file, root_path).replace("\\", "/")
    for dep in data.get("dependencies", []):
        pkg_name = dep.get("name", "")
        pkg_ver = dep.get("version", "")
        for vuln in dep.get("vulns", []):
            cve_id = vuln.get("id") or (vuln.get("aliases") or [""])[0]
            fix_versions = vuln.get("fix_versions") or []
            fix_ver = fix_versions[0] if fix_versions else "latest"
            desc = vuln.get("description", "")[:200]
            findings.append(Finding(
                id=f"dep-pip-{pkg_name}-{cve_id.lower()}",
                dimension=ScanDimension.DEPENDENCY,
                severity=Severity.HIGH,
                title=f"Vulnerable dependency: {pkg_name} {pkg_ver}",
                description=desc or f"Known vulnerability {cve_id}",
                cwe=cve_id,
                file_path=rel_path,
                line=1,
                fixes=[
                    Fix(
                        description=f"Upgrade {pkg_name} to {fix_ver}",
                        type="edit",
                        effort="low",
                        edit_operations=[
                            EditOperation(
                                file=rel_path,
                                old_string=f"{pkg_name}=={pkg_ver}",
                                new_string=f"{pkg_name}=={fix_ver}",
                                description=(
                                    f"Update {pkg_name} from {pkg_ver} "
                                    f"to {fix_ver}"
                                ),
                            )
                        ],
                    )
                ],
            ))
    return findings


def _try_bandit(root_path: str) -> Optional[list[Finding]]:
    """
    尝试用 bandit 扫描 Python 代码。

    成功返回 Finding 列表；工具不可用或失败返回 None（调用方降级）。
    """
    if not USE_EXTERNAL_TOOLS:
        return None

    stdout = _run_tool(
        ["bandit", "-r", ".", "-f", "json", "--quiet"],
        root_path,
    )
    if stdout is None or stdout[1] != 0:
        return None

    try:
        data = json.loads(stdout[0])
    except (json.JSONDecodeError, TypeError):
        return None

    # bandit test_id → (漏洞类型, 严重度)
    test_map = {
        "B601": ("sql-injection", Severity.CRITICAL),
        "B602": ("sql-injection", Severity.HIGH),
        "B608": ("sql-injection", Severity.HIGH),
        "B603": ("command-injection", Severity.HIGH),
        "B604": ("command-injection", Severity.HIGH),
        "B605": ("command-injection", Severity.HIGH),
        "B606": ("command-injection", Severity.CRITICAL),
        "B607": ("command-injection", Severity.CRITICAL),
        "B610": ("path-traversal", Severity.HIGH),
        "B611": ("path-traversal", Severity.HIGH),
        "B201": ("eval-usage", Severity.HIGH),
        "B301": ("unsafe-deserialization", Severity.CRITICAL),
        "B302": ("unsafe-deserialization", Severity.CRITICAL),
        "B303": ("unsafe-deserialization", Severity.CRITICAL),
        "B506": ("unsafe-deserialization", Severity.HIGH),
        "B401": ("command-injection", Severity.MEDIUM),
    }
    cwe_map = {
        "sql-injection": "CWE-89",
        "command-injection": "CWE-78",
        "path-traversal": "CWE-22",
        "eval-usage": "CWE-94",
        "unsafe-deserialization": "CWE-502",
    }

    findings = []
    for res in data.get("results", []):
        test_id = res.get("test_id", "")
        if test_id not in test_map:
            continue
        vuln_type, severity = test_map[test_id]
        fname = res.get("filename", "")
        rel_path = os.path.relpath(fname, root_path).replace("\\", "/")
        line = res.get("line_number") or 1
        findings.append(Finding(
            id=f"sast-bandit-{test_id}-{os.path.splitext(os.path.basename(fname))[0]}",
            dimension=ScanDimension.SAST,
            severity=severity,
            title=res.get("issue_text", f"Bandit {test_id}"),
            description=(
                f"Bandit {test_id}: {res.get('issue_text', '')} "
                f"(confidence: {res.get('issue_confidence', '?')})"
            ),
            cwe=cwe_map.get(vuln_type, ""),
            file_path=rel_path,
            line=line,
            code_snippet=(res.get("code") or "")[:200],
        ))
    return findings


# =====================================================================
# 阶段 1: 项目探针
# =====================================================================

def probe_project(root_path: str) -> ProbeResult:
    """
    自动检测项目技术栈。

    1. 遍历文件后缀分布 → 确定语言
    2. 检查特征文件 → 确定框架
    3. 识别依赖管理工具和配置文件
    4. 确定需要加载的规则集
    """
    file_count = {}
    dep_files = {}
    config_files = {}
    has_dockerfile = False
    has_cicd = False
    has_terraform = False

    # 遍历项目根目录
    for dirpath, dirnames, filenames in os.walk(root_path):
        # 跳过排除目录
        rel = os.path.relpath(dirpath, root_path).replace("\\", "/")
        if any(part in rel.split("/") for part in
               ("node_modules", "venv", ".git", "__pycache__",
                "dist", "build", ".next", ".cache", "target",
                "vendor", ".tox", "env")):
            continue

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            ext = Path(fname).suffix.lower()
            if ext:
                file_count[ext] = file_count.get(ext, 0) + 1

            rel_path = os.path.relpath(fpath, root_path).replace("\\", "/")

            # 依赖文件检测
            if fname in ("requirements.txt", "Pipfile"):
                dep_files["pip"] = rel_path
            elif fname in ("pyproject.toml",):
                dep_files["pip"] = rel_path
            elif fname in ("package.json", "package-lock.json", "yarn.lock"):
                dep_files["npm"] = rel_path
            elif fname in ("go.mod",):
                dep_files["go"] = rel_path
            elif fname in ("pom.xml",):
                dep_files["maven"] = rel_path
            elif fname in ("build.gradle", "build.gradle.kts"):
                dep_files["gradle"] = rel_path
            elif fname in ("Gemfile",):
                dep_files["bundler"] = rel_path
            elif fname in ("Cargo.toml",):
                dep_files["cargo"] = rel_path
            elif fname in ("composer.json",):
                dep_files["composer"] = rel_path

            # 配置文件检测
            if fname == "settings.py":
                config_files["django_settings"] = rel_path
            elif fname == "Dockerfile" or fname.startswith("Dockerfile."):
                has_dockerfile = True
            elif fname in (".github/workflows/main.yml",
                           ".github/workflows/ci.yml",
                           ".gitlab-ci.yml", "Jenkinsfile"):
                has_cicd = True

            # Terraform 检测
            if fname.endswith((".tf", ".tfvars")):
                has_terraform = True

    languages = detect_language(file_count)

    # 框架检测
    frameworks = []
    lang_lower = [l.lower() for l in languages]

    if "python" in lang_lower:
        if "django_settings" in config_files:
            frameworks.append("django")
        elif "Flask" in str(config_files):
            frameworks.append("flask")
        # 进一步检查 FastAPI
        for fname in glob_files(root_path, "**/*.py"):
            content = read_file_content(os.path.join(root_path, fname))
            if content and "from fastapi" in content:
                if "fastapi" not in frameworks:
                    frameworks.append("fastapi")
                    break

    if "javascript" in lang_lower or "typescript" in lang_lower:
        pkg_json = glob_files(root_path, "**/package.json")
        for pj in pkg_json[:5]:
            content = read_file_content(os.path.join(root_path, pj))
            if content:
                if re.search(r'"express"\s*:', content):
                    frameworks.append("express")
                if re.search(r'"@nestjs/core"\s*:', content):
                    frameworks.append("nestjs")
                if re.search(r'"react"\s*:', content):
                    frameworks.append("react")
                if re.search(r'"vue"\s*:', content):
                    frameworks.append("vue")
                if re.search(r'"next"\s*:', content):
                    frameworks.append("nextjs")

    if "go" in lang_lower:
        go_mod = glob_files(root_path, "**/go.mod")
        for gm in go_mod[:3]:
            content = read_file_content(os.path.join(root_path, gm))
            if content:
                if "gin-gonic/gin" in content:
                    frameworks.append("gin")
                if "gorm.io/gorm" in content:
                    frameworks.append("gorm")

    if "java" in lang_lower:
        for fname in glob_files(root_path, "**/pom.xml")[:5]:
            content = read_file_content(os.path.join(root_path, fname))
            if content and "spring-boot" in content:
                frameworks.append("spring")
                break

    # 规则集
    rules_to_load = ["base"]
    lang_rules = {
        "python": "python", "javascript": "javascript",
        "typescript": "javascript", "go": "go", "java": "java",
        "ruby": "ruby", "rust": "rust", "php": "php", "csharp": "csharp",
    }
    for lang in languages:
        if lang in lang_rules:
            r = lang_rules[lang]
            if r not in rules_to_load:
                rules_to_load.append(r)

    framework_rules = {
        "django": "django", "flask": "flask", "fastapi": "python",
        "express": "express", "nestjs": "javascript", "react": "javascript",
        "vue": "javascript", "nextjs": "javascript",
        "spring": "spring", "rails": "ruby", "laravel": "php",
        "gin": "go", "gorm": "go",
    }
    for fw in frameworks:
        if fw in framework_rules:
            r = framework_rules[fw]
            if r not in rules_to_load:
                rules_to_load.append(r)

    if has_dockerfile and "docker" not in rules_to_load:
        rules_to_load.append("docker")
    if has_cicd and "cicd" not in rules_to_load:
        rules_to_load.append("cicd")
    if has_terraform and "terraform" not in rules_to_load:
        rules_to_load.append("terraform")

    # 依赖管理器列表
    dep_managers = list(dep_files.keys())

    return ProbeResult(
        languages=languages,
        frameworks=frameworks,
        dep_managers=dep_managers,
        has_dockerfile=has_dockerfile,
        has_cicd=has_cicd,
        config_files=config_files,
        file_stats=file_count,
        rules_to_load=rules_to_load,
    )


# =====================================================================
# 阶段 2: 扫描器实现
# =====================================================================

def _condition_match_line(condition: dict, content: str) -> Optional[int]:
    """
    返回规则条件在文件内容中匹配的行号（1 基），无法确定时返回 None。

    Args:
        condition: 条件定义
        content: 文件内容

    Returns:
        匹配行号，或 None
    """
    ctype = condition.get("type", "")
    pattern = condition.get("pattern", "")
    try:
        if ctype in ("regex_in_file", "line_matches"):
            m = re.search(pattern, content, re.MULTILINE)
            if m:
                return content[:m.start()].count("\n") + 1
        elif ctype == "file_contains":
            idx = content.find(pattern)
            if idx >= 0:
                return content[:idx].count("\n") + 1
        elif ctype == "value_equals":
            m = re.search(
                rf"{re.escape(condition['key'])}\s*[=:]\s*"
                rf"{re.escape(condition['value'])}",
                content
            )
            if m:
                return content[:m.start()].count("\n") + 1
    except (re.error, KeyError):
        pass
    return None


def scan_config(probe: ProbeResult, root_path: str,
                ignore_rules: list[dict],
                changed_files: Optional[set[str]] = None) -> list[Finding]:
    """
    配置安全扫描。

    读取对应框架的 YAML 规则文件，对配置文件进行匹配检查。

    Args:
        probe: 项目探测结果
        root_path: 项目根目录
        ignore_rules: 假阳性忽略规则
        changed_files: 增量模式下的变更文件绝对路径集合（None=全量扫描）
    """
    findings = []
    rules_dir = os.path.join(os.path.dirname(__file__), "rules")

    rule_categories = []
    for r in probe.rules_to_load:
        rule_dir = os.path.join(rules_dir, r)
        if os.path.isdir(rule_dir):
            rule_categories.append(rule_dir)
    rule_categories.append(os.path.join(rules_dir, "base"))

    # 去重
    seen = set()
    for cat_dir in rule_categories:
        if not os.path.isdir(cat_dir):
            continue
        for yml_file in glob_files(cat_dir, "*.yml"):
            if yml_file in seen:
                continue
            seen.add(yml_file)

            content = read_file_content(yml_file)
            if not content:
                continue

            rule = parse_yaml_rule(content)
            if not rule:
                continue

            # 检查语言和框架过滤
            rule_langs = rule.get("languages", [])
            rule_fws = rule.get("frameworks", [])

            if rule_langs:
                lang_match = any(
                    l in probe.languages for l in rule_langs
                )
                if not lang_match:
                    continue

            if rule_fws:
                fw_match = any(
                    f in probe.frameworks for f in rule_fws
                )
                if not fw_match:
                    continue

            # 匹配检测条件
            detect_conditions = rule.get("detect", [])
            # path → (line_no, file_content)
            matched_paths: dict[str, tuple[Optional[int], str]] = {}

            for cond in detect_conditions:
                cond_type = cond.get("type", "")
                cond_path = cond.get("path", "")
                cond_pattern = cond.get("pattern", "")

                if not cond_path:
                    continue

                target_files = glob_files(root_path, cond_path)
                for tf in target_files:
                    if changed_files is not None and os.path.abspath(tf) not in changed_files:
                        continue
                    if should_exclude_path(tf):
                        continue
                    file_content = read_file_content(tf)
                    if file_content is None:
                        continue

                    condition = {
                        "type": cond_type,
                        "pattern": cond_pattern,
                        **({k: v for k, v in cond.items()
                           if k not in ("type", "path", "pattern")}),
                    }

                    if match_rule_condition(condition, file_content):
                        line_no = _condition_match_line(
                            condition, file_content
                        )
                        existing = matched_paths.get(tf)
                        if existing is None or (existing[0] is None and line_no):
                            matched_paths[tf] = (line_no, file_content)

            for tf, (line_no, file_content) in matched_paths.items():
                rel_path = os.path.relpath(tf, root_path).replace("\\", "/")
                line = line_no or 1

                # 检查是否被忽略规则排除
                if utils_is_ignored(rel_path, line, rule.get("id", ""), ignore_rules):
                    continue

                # 生成 Finding
                finding = Finding(
                    id=f"config-{rule.get('id', 'unknown')}",
                    dimension=ScanDimension.CONFIG,
                    severity=Severity(rule.get("severity", "medium")),
                    title=rule.get("name", "Unknown config issue"),
                    description=rule.get("description", ""),
                    cwe=rule.get("cwe", ""),
                    owasp=rule.get("owasp", ""),
                    file_path=rel_path,
                    line=line,
                )

                # 生成修复方案：每个 fix 定义只携带自己的编辑操作
                for fix_def in rule.get("fix", []):
                    mini_rule = {"fix": [fix_def]}
                    fix_ops = generate_fix_operations(
                        mini_rule, rel_path, file_content
                    )
                    ops = [
                        EditOperation(
                            file=op["file"],
                            old_string=op["old_string"],
                            new_string=op["new_string"],
                            description=op.get("description", ""),
                        )
                        for op in fix_ops
                    ]
                    finding.fixes.append(Fix(
                        description=fix_def.get(
                            "description", "Apply fix"
                        ),
                        type=fix_def.get("type", "config"),
                        effort=fix_def.get("effort", "medium"),
                        edit_operations=ops,
                    ))

                findings.append(finding)

    return findings


def scan_dependencies(probe: ProbeResult, root_path: str,
                      ignore_rules: list[dict],
                      changed_files: Optional[set[str]] = None) -> list[Finding]:
    """
    依赖漏洞扫描。

    尝试使用 pip-audit / npm audit，降级使用内置 CVE 数据库。

    Args:
        probe: 项目探测结果
        root_path: 项目根目录
        ignore_rules: 假阳性忽略规则
        changed_files: 增量模式下的变更文件绝对路径集合（None=全量扫描）
    """
    findings = []

    # Python 依赖扫描
    if "pip" in probe.dep_managers or any(
        pf.endswith(("requirements.txt", "pyproject.toml", "Pipfile"))
        for pf in probe.config_files.values()
    ):
        py_findings = _scan_python_deps(root_path, probe, ignore_rules,
                                        changed_files)
        findings.extend(py_findings)

    # Node.js 依赖扫描
    if "npm" in probe.dep_managers:
        npm_findings = _scan_npm_deps(root_path, probe, ignore_rules,
                                      changed_files)
        findings.extend(npm_findings)

    # Go 依赖扫描
    if "go" in probe.dep_managers:
        go_findings = _scan_go_deps(root_path, probe, ignore_rules,
                                    changed_files)
        findings.extend(go_findings)

    # Ruby 依赖扫描
    if "bundler" in probe.dep_managers:
        ruby_findings = _scan_ruby_deps(root_path, probe, ignore_rules,
                                        changed_files)
        findings.extend(ruby_findings)

    # Rust 依赖扫描
    if "cargo" in probe.dep_managers:
        rust_findings = _scan_rust_deps(root_path, probe, ignore_rules,
                                        changed_files)
        findings.extend(rust_findings)

    # PHP 依赖扫描
    if "composer" in probe.dep_managers:
        php_findings = _scan_php_deps(root_path, probe, ignore_rules,
                                      changed_files)
        findings.extend(php_findings)

    return findings


def _parse_requirements(content: str) -> list[tuple[str, str, int]]:
    """解析 requirements.txt，返回 [(包名, 版本, 行号)]"""
    results = []
    for i, line in enumerate(content.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # 支持 ==, >=, ~=, !=
        for sep in ("==", ">=", "~=", "!=", "<=", "<", ">"):
            if sep in line:
                pkg, ver = line.split(sep, 1)
                pkg = pkg.strip().lower()
                ver = ver.strip().split("#")[0].strip()
                results.append((pkg, ver, i))
                break
    return results


def _scan_python_deps(root_path: str, probe: ProbeResult,
                      ignore_rules: list[dict],
                      changed_files: Optional[set[str]] = None) -> list[Finding]:
    """扫描 Python 依赖（优先 pip-audit，降级内置 CVE 库）"""
    findings = []

    for dep_type in ("requirements.txt",):
        dep_files = glob_files(root_path, f"**/{dep_type}")
        for df in dep_files:
            if changed_files is not None and os.path.abspath(df) not in changed_files:
                continue
            if should_exclude_path(df):
                continue
            content = read_file_content(df)
            if not content:
                continue

            rel_path = os.path.relpath(df, root_path).replace("\\", "/")

            # 首选 pip-audit（若可用）
            pip_audit_findings = _try_pip_audit(df, root_path)
            if pip_audit_findings is not None:
                findings.extend(pip_audit_findings)
                continue

            # 降级：内置 CVE 库
            packages = _parse_requirements(content)

            for pkg_name, pkg_ver, line_no in packages:
                if utils_is_ignored(rel_path, line_no, pkg_name, ignore_rules):
                    continue

                vulns = check_python_package(pkg_name, pkg_ver)
                for vuln in vulns:
                    finding = Finding(
                        id=f"dep-pip-{pkg_name}-{vuln['cve_id'].lower()}",
                        dimension=ScanDimension.DEPENDENCY,
                        severity=Severity(vuln["severity"]),
                        title=f"Vulnerable dependency: {pkg_name} {pkg_ver}",
                        description=vuln["description"],
                        cwe=vuln.get("cve_id", ""),
                        file_path=rel_path,
                        line=line_no,
                        fixes=[
                            Fix(
                                description=(
                                    f"Upgrade {pkg_name} to {vuln['fixed_version']}"
                                ),
                                type="edit",
                                effort="low",
                                edit_operations=[
                                    EditOperation(
                                        file=rel_path,
                                        old_string=f"{pkg_name}=={pkg_ver}",
                                        new_string=(
                                            f"{pkg_name}=={vuln['fixed_version']}"
                                        ),
                                        description=(
                                            f"Update {pkg_name} from {pkg_ver} "
                                            f"to {vuln['fixed_version']}"
                                        ),
                                    )
                                ],
                            )
                        ],
                    )
                    findings.append(finding)
    return findings


def _scan_npm_deps(root_path: str, probe: ProbeResult,
                   ignore_rules: list[dict],
                   changed_files: Optional[set[str]] = None) -> list[Finding]:
    """扫描 Node.js 依赖（使用内置数据库）"""
    findings = []
    pkg_json_files = glob_files(root_path, "**/package.json")

    for pj in pkg_json_files:
        if changed_files is not None and os.path.abspath(pj) not in changed_files:
            continue
        if should_exclude_path(pj):
            continue
        content = read_file_content(pj)
        if not content:
            continue

        rel_path = os.path.relpath(pj, root_path).replace("\\", "/")

        # 简易解析 dependencies
        deps_match = re.search(
            r'"dependencies"\s*:\s*\{(.+?)\}',
            content, re.DOTALL
        )
        if not deps_match:
            continue

        deps_section = deps_match.group(1)
        for dep_match in re.finditer(
            r'"([^"]+)"\s*:\s*"\^?([^"]+)"', deps_section
        ):
            pkg_name = dep_match.group(1)
            pkg_ver = dep_match.group(2)

            if utils_is_ignored(rel_path, 0, pkg_name, ignore_rules):
                continue

            vulns = check_npm_package(pkg_name, pkg_ver)
            for vuln in vulns:
                finding = Finding(
                    id=f"dep-npm-{pkg_name}-{vuln['cve_id'].lower()}",
                    dimension=ScanDimension.DEPENDENCY,
                    severity=Severity(vuln["severity"]),
                    title=f"Vulnerable npm package: {pkg_name} {pkg_ver}",
                    description=vuln["description"],
                    cwe=vuln.get("cve_id", ""),
                    file_path=rel_path,
                    line=1,
                    fixes=[
                        Fix(
                            description=(
                                f"Upgrade {pkg_name} to {vuln['fixed_version']}"
                            ),
                            type="edit",
                            effort="low",
                        )
                    ],
                )
                findings.append(finding)
    return findings


def _scan_go_deps(root_path: str, probe: ProbeResult,
                  ignore_rules: list[dict],
                  changed_files: Optional[set[str]] = None) -> list[Finding]:
    """扫描 Go 依赖"""
    findings = []
    go_mod_files = glob_files(root_path, "**/go.mod")

    for gm in go_mod_files:
        if changed_files is not None and os.path.abspath(gm) not in changed_files:
            continue
        if should_exclude_path(gm):
            continue
        content = read_file_content(gm)
        if not content:
            continue

        rel_path = os.path.relpath(gm, root_path).replace("\\", "/")

        # 解析 require 块中的依赖
        for req_match in re.finditer(
            r'require\s+\((.+?)\)', content, re.DOTALL
        ):
            block = req_match.group(1)
            for line in block.split("\n"):
                parts = line.strip().split()
                if len(parts) >= 2:
                    pkg = parts[0]
                    ver = parts[1]

                    if utils_is_ignored(rel_path, 0, pkg, ignore_rules):
                        continue

                    vulns = check_go_package(pkg, ver)
                    for vuln in vulns:
                        finding = Finding(
                            id=f"dep-go-{pkg.split('/')[-1]}-{vuln['cve_id'].lower()}",
                            dimension=ScanDimension.DEPENDENCY,
                            severity=Severity(vuln["severity"]),
                            title=f"Vulnerable Go module: {pkg} {ver}",
                            description=vuln["description"],
                            cwe=vuln.get("cve_id", ""),
                            file_path=rel_path,
                            line=1,
                        )
                        findings.append(finding)
    return findings


def _scan_ruby_deps(root_path: str, probe: ProbeResult,
                    ignore_rules: list[dict],
                    changed_files: Optional[set[str]] = None) -> list[Finding]:
    """扫描 Ruby (Bundler) 依赖（使用内置数据库）"""
    from dependency_db import check_bundler_package
    findings = []
    gem_files = glob_files(root_path, "**/Gemfile")

    for gf in gem_files:
        if changed_files is not None and os.path.abspath(gf) not in changed_files:
            continue
        if should_exclude_path(gf):
            continue
        content = read_file_content(gf)
        if not content:
            continue

        rel_path = os.path.relpath(gf, root_path).replace("\\", "/")

        for line in content.split("\n"):
            m = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", line)
            if not m:
                continue
            pkg_name, pkg_ver = m.group(1), m.group(2)

            if utils_is_ignored(rel_path, 0, pkg_name, ignore_rules):
                continue

            vulns = check_bundler_package(pkg_name, pkg_ver)
            for vuln in vulns:
                findings.append(Finding(
                    id=f"dep-ruby-{pkg_name}-{vuln['cve_id'].lower()}",
                    dimension=ScanDimension.DEPENDENCY,
                    severity=Severity(vuln["severity"]),
                    title=f"Vulnerable gem: {pkg_name} {pkg_ver}",
                    description=vuln["description"],
                    cwe=vuln.get("cve_id", ""),
                    file_path=rel_path,
                    line=1,
                ))
    return findings


def _scan_rust_deps(root_path: str, probe: ProbeResult,
                    ignore_rules: list[dict],
                    changed_files: Optional[set[str]] = None) -> list[Finding]:
    """扫描 Rust (Cargo) 依赖（使用内置数据库）"""
    from dependency_db import check_cargo_package
    findings = []
    cargo_files = glob_files(root_path, "**/Cargo.toml")

    for cf in cargo_files:
        if changed_files is not None and os.path.abspath(cf) not in changed_files:
            continue
        if should_exclude_path(cf):
            continue
        content = read_file_content(cf)
        if not content:
            continue

        rel_path = os.path.relpath(cf, root_path).replace("\\", "/")

        # 解析 [dependencies] 块
        for m in re.finditer(
            r'^([a-zA-Z0-9_\-]+)\s*=\s*\{\s*version\s*=\s*["\']([^"\']+)["\']',
            content, re.MULTILINE
        ):
            pkg_name, pkg_ver = m.group(1), m.group(2)
            if utils_is_ignored(rel_path, 0, pkg_name, ignore_rules):
                continue
            vulns = check_cargo_package(pkg_name, pkg_ver)
            for vuln in vulns:
                findings.append(Finding(
                    id=f"dep-rust-{pkg_name}-{vuln['cve_id'].lower()}",
                    dimension=ScanDimension.DEPENDENCY,
                    severity=Severity(vuln["severity"]),
                    title=f"Vulnerable crate: {pkg_name} {pkg_ver}",
                    description=vuln["description"],
                    cwe=vuln.get("cve_id", ""),
                    file_path=rel_path,
                    line=1,
                ))
    return findings


def _scan_php_deps(root_path: str, probe: ProbeResult,
                   ignore_rules: list[dict],
                   changed_files: Optional[set[str]] = None) -> list[Finding]:
    """扫描 PHP (Composer) 依赖（使用内置数据库）"""
    from dependency_db import check_composer_package
    findings = []
    composer_files = glob_files(root_path, "**/composer.json")

    for cf in composer_files:
        if changed_files is not None and os.path.abspath(cf) not in changed_files:
            continue
        if should_exclude_path(cf):
            continue
        content = read_file_content(cf)
        if not content:
            continue

        rel_path = os.path.relpath(cf, root_path).replace("\\", "/")

        for section in ("require", "require-dev"):
            sec_match = re.search(
                r'"{0}"\s*:\s*\{{(.+?)\}}'.format(section),
                content, re.DOTALL
            )
            if not sec_match:
                continue
            for dep_match in re.finditer(
                r'"([^"]+)"\s*:\s*"\^?([^"]+)"', sec_match.group(1)
            ):
                pkg_name, pkg_ver = dep_match.group(1), dep_match.group(2)
                if utils_is_ignored(rel_path, 0, pkg_name, ignore_rules):
                    continue
                vulns = check_composer_package(pkg_name, pkg_ver)
                for vuln in vulns:
                    findings.append(Finding(
                        id=f"dep-php-{pkg_name}-{vuln['cve_id'].lower()}",
                        dimension=ScanDimension.DEPENDENCY,
                        severity=Severity(vuln["severity"]),
                        title=f"Vulnerable package: {pkg_name} {pkg_ver}",
                        description=vuln["description"],
                        cwe=vuln.get("cve_id", ""),
                        file_path=rel_path,
                        line=1,
                    ))
    return findings


def scan_sast(probe: ProbeResult, root_path: str,
              ignore_rules: list[dict],
              changed_files: Optional[set[str]] = None) -> list[Finding]:
    """
    SAST 静态代码安全分析。

    使用 sast_patterns.py 中的内置正则模式库匹配源代码。
    """
    findings = []

    # 语言 → 扩展名映射
    lang_exts = {
        "python": [".py"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
        "go": [".go"],
        "java": [".java"],
        "ruby": [".rb"],
        "rust": [".rs"],
        "php": [".php"],
        "csharp": [".cs"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".hpp"],
        "swift": [".swift"],
        "kotlin": [".kt", ".kts"],
    }

    severity_map = {
        "sql-injection": Severity.CRITICAL,
        "command-injection": Severity.CRITICAL,
        "unsafe-deserialization": Severity.CRITICAL,
        "hardcoded-credentials": Severity.CRITICAL,
        "xss": Severity.HIGH,
        "path-traversal": Severity.HIGH,
        "ssrf": Severity.HIGH,
        "eval-usage": Severity.HIGH,
        "prototype-pollution": Severity.HIGH,
        "insecure-random": Severity.MEDIUM,
        "weak-tls": Severity.MEDIUM,
        "xxe": Severity.MEDIUM,
    }

    # 首选 bandit（Python，若可用）
    if "python" in [l.lower() for l in probe.languages]:
        bandit_findings = _try_bandit(root_path)
        if bandit_findings is not None:
            findings.extend(bandit_findings)

    cwe_map = {
        "sql-injection": "CWE-89",
        "command-injection": "CWE-78",
        "path-traversal": "CWE-22",
        "xss": "CWE-79",
        "unsafe-deserialization": "CWE-502",
        "ssrf": "CWE-918",
        "eval-usage": "CWE-94",
        "hardcoded-credentials": "CWE-798",
        "prototype-pollution": "CWE-1321",
        "insecure-random": "CWE-338",
        "weak-tls": "CWE-327",
        "xxe": "CWE-611",
    }

    for lang in probe.languages:
        exts = lang_exts.get(lang, [])
        if not exts:
            continue

        # 收集所有该语言的源文件
        for ext in exts:
            files = glob_files(root_path, f"**/*{ext}")
            for fpath in files:
                if changed_files is not None and os.path.abspath(fpath) not in changed_files:
                    continue
                if should_exclude_path(fpath):
                    continue

                rel_path = os.path.relpath(fpath, root_path).replace("\\", "/")
                content = read_file_content(fpath)
                if not content:
                    continue

                # Python 文件额外运行 AST 扫描（更精确的污点分析）
                results = match_in_content(content, lang)
                if lang == "python":
                    results.extend(scan_python_source(content))

                for r in results:
                    if utils_is_ignored(
                        rel_path, r["line"],
                        f"sast-{r['vuln_type']}", ignore_rules
                    ):
                        continue

                    vuln_type = r["vuln_type"]
                    finding = Finding(
                        id=f"sast-{vuln_type}-{Path(rel_path).stem}",
                        dimension=ScanDimension.SAST,
                        severity=severity_map.get(
                            vuln_type, Severity.MEDIUM
                        ),
                        title=r["description"],
                        description=(
                            f"Pattern matched: {r['match']} "
                            f"in {rel_path}:{r['line']}"
                        ),
                        cwe=cwe_map.get(vuln_type, ""),
                        file_path=rel_path,
                        line=r["line"],
                        code_snippet=r["match"],
                    )
                    findings.append(finding)

    return findings


def scan_auth(probe: ProbeResult, root_path: str,
              ignore_rules: list[dict],
              changed_files: Optional[set[str]] = None) -> list[Finding]:
    """
    认证与授权安全扫描。

    覆盖与 auth-scanner.md Agent 同等级的检查项：
    - 会话管理: Secure/HttpOnly/SameSite Cookie、CSRF Cookie
    - 认证机制: 默认认证类、Basic Auth、Token 管理
    - 授权控制: 默认权限类、AllowAny
    """
    findings = []

    if "django" in probe.frameworks:
        settings_files = glob_files(root_path, "**/settings.py")
        for sf in settings_files:
            if changed_files is not None and os.path.abspath(sf) not in changed_files:
                continue
            rel_path = os.path.relpath(sf, root_path).replace("\\", "/")
            content = read_file_content(sf) or ""

            # 配置检查表: (检查函数, rule_id, title, desc, severity, cwe)
            checks = [
                (lambda c: "SESSION_COOKIE_SECURE" not in c,
                 "session-cookie-secure", "Session Cookie Secure flag not set",
                 "SESSION_COOKIE_SECURE 未配置，会话 Cookie 会通过 HTTP 明文传输。",
                 Severity.MEDIUM, "CWE-614"),
                (lambda c: "SESSION_COOKIE_HTTPONLY" not in c,
                 "session-cookie-httponly", "Session Cookie HttpOnly flag not set",
                 "SESSION_COOKIE_HTTPONLY 未配置，Cookie 可被 JavaScript 读取，增加 XSS 窃取会话的风险。",
                 Severity.LOW, "CWE-1004"),
                (lambda c: "SESSION_COOKIE_SAMESITE" not in c,
                 "session-cookie-samesite", "Session Cookie SameSite not configured",
                 "SESSION_COOKIE_SAMESITE 未配置，跨站请求可能携带 Cookie，增加 CSRF 风险。",
                 Severity.LOW, "CWE-1275"),
                (lambda c: "CSRF_COOKIE_SECURE" not in c,
                 "csrf-cookie-secure", "CSRF Cookie Secure flag not set",
                 "CSRF_COOKIE_SECURE 未配置，CSRF Token Cookie 可能通过 HTTP 泄露。",
                 Severity.MEDIUM, "CWE-614"),
                (lambda c: "DEFAULT_AUTHENTICATION_CLASSES" not in c and "REST_FRAMEWORK" in c,
                 "default-auth-classes", "DRF default authentication classes not configured",
                 "配置了 REST_FRAMEWORK 但未设置 DEFAULT_AUTHENTICATION_CLASSES，认证行为不明确。",
                 Severity.MEDIUM, "CWE-287"),
                (lambda c: "DEFAULT_PERMISSION_CLASSES" not in c and "REST_FRAMEWORK" in c,
                 "default-permission-classes", "DRF default permission classes not configured",
                 "配置了 REST_FRAMEWORK 但未设置 DEFAULT_PERMISSION_CLASSES，默认权限可能过于宽松。",
                 Severity.MEDIUM, "CWE-862"),
                (lambda c: bool(re.search(r"DEFAULT_PERMISSION_CLASSES.*AllowAny", c)),
                 "allow-any-default", "DRF default permission is AllowAny",
                 "DEFAULT_PERMISSION_CLASSES 设置为 AllowAny，所有端点默认公开访问。",
                 Severity.HIGH, "CWE-862"),
                (lambda c: "BasicAuthentication" in c,
                 "basic-auth-enabled", "Basic Authentication enabled",
                 "启用了 BasicAuthentication，凭据以 Base64 传输，易被截获。",
                 Severity.MEDIUM, "CWE-522"),
            ]

            for check, rule_id, title, desc, sev, cwe in checks:
                if check(content):
                    finding = Finding(
                        id=f"auth-django-{rule_id}",
                        dimension=ScanDimension.AUTH,
                        severity=sev,
                        title=title,
                        description=desc,
                        cwe=cwe,
                        file_path=rel_path,
                        line=1,
                    )
                    if not utils_is_ignored(rel_path, 0, finding.id, ignore_rules):
                        findings.append(finding)

        # Token 在 URL 中传输（视图层）
        for ext in (".py", ".js", ".ts"):
            for fpath in glob_files(root_path, f"**/*{ext}"):
                if changed_files is not None and os.path.abspath(fpath) not in changed_files:
                    continue
                if should_exclude_path(fpath):
                    continue
                rel_path = os.path.relpath(fpath, root_path).replace("\\", "/")
                content = read_file_content(fpath)
                if not content:
                    continue
                # 检测 token/session_key 出现在 URL 查询参数
                for m in re.finditer(
                    r"['\"](?:[?&](?:token|session[_-]?key|auth)=)|\?token=",
                    content
                ):
                    line = content[:m.start()].count("\n") + 1
                    finding = Finding(
                        id="auth-token-in-url",
                        dimension=ScanDimension.AUTH,
                        severity=Severity.HIGH,
                        title="Token/Session key transmitted in URL",
                        description="检测到 token 或 session key 可能出现在 URL 中，会泄露到日志和浏览器历史。",
                        cwe="CWE-598",
                        file_path=rel_path,
                        line=line,
                    )
                    if not utils_is_ignored(rel_path, line, finding.id, ignore_rules):
                        findings.append(finding)
                    break  # 每个文件只报一次

    # Express/Node.js: Helmet 缺失会削弱安全头
    if "express" in probe.frameworks or "nestjs" in probe.frameworks:
        for fpath in glob_files(root_path, "**/*.{js,ts}"):
            if changed_files is not None and os.path.abspath(fpath) not in changed_files:
                continue
            if should_exclude_path(fpath):
                continue
            rel_path = os.path.relpath(fpath, root_path).replace("\\", "/")
            content = read_file_content(fpath)
            if not content:
                continue
            if ("helmet" not in content
                    and re.search(r"express\(\)|app\.use\(|createServer\(", content)):
                finding = Finding(
                    id="auth-express-helmet-missing",
                    dimension=ScanDimension.AUTH,
                    severity=Severity.MEDIUM,
                    title="Helmet middleware not used",
                    description="Express 应用未使用 Helmet 中间件，安全响应头缺失。",
                    cwe="CWE-693",
                    file_path=rel_path,
                    line=1,
                )
                if not utils_is_ignored(rel_path, 0, finding.id, ignore_rules):
                    findings.append(finding)
                break

    return findings


def scan_business(probe: ProbeResult, root_path: str,
                  ignore_rules: list[dict],
                  changed_files: Optional[set[str]] = None) -> list[Finding]:
    """
    业务逻辑安全扫描。

    分析代码结构，检测常见业务逻辑漏洞。
    """
    findings = []

    # 检测登录接口速率限制
    for ext in (".py", ".js", ".ts", ".go", ".java"):
        files = glob_files(root_path, f"**/*{ext}")
        for fpath in files:
            if changed_files is not None and os.path.abspath(fpath) not in changed_files:
                continue
            if should_exclude_path(fpath):
                continue

            rel_path = os.path.relpath(fpath, root_path).replace("\\", "/")
            content = read_file_content(fpath)
            if not content:
                continue

            # 检测登录端点缺乏速率限制
            for match in re.finditer(
                r'def\s+(login|signin|sign_in)\s*\(',
                content
            ):
                line_no = content[:match.start()].count('\n') + 1
                if utils_is_ignored(rel_path, line_no,
                                    "business-no-rate-limit", ignore_rules):
                    continue

                # 检查该函数或视图类是否有 throttle/ratelimit 装饰器
                func_start = max(0, content.rfind('\n', 0, match.start()))
                func_header = content[func_start:match.end() + 200]

                if not re.search(
                    r'@.*(throttle|ratelimit|rate_limit|throttle_classes)',
                    func_header
                ):
                    findings.append(Finding(
                        id="business-no-rate-limit-login",
                        dimension=ScanDimension.BUSINESS,
                        severity=Severity.MEDIUM,
                        title="Login endpoint without rate limiting",
                        description=(
                            "Login endpoint detected without rate limiting. "
                            "This could allow brute force attacks."
                        ),
                        cwe="CWE-307",
                        file_path=rel_path,
                        line=line_no,
                    ))

            # 检测 AllowAny 权限
            for match in re.finditer(
                r'permission_classes\s*=\s*\[.*AllowAny.*\]',
                content
            ):
                line_no = content[:match.start()].count('\n') + 1
                if utils_is_ignored(rel_path, line_no,
                                    "business-allow-any", ignore_rules):
                    continue

                findings.append(Finding(
                    id="business-allow-any-permission",
                    dimension=ScanDimension.BUSINESS,
                    severity=Severity.MEDIUM,
                    title="Endpoint with AllowAny permission",
                    description=(
                        "ViewSet or API endpoint uses AllowAny permission. "
                        "Verify this is intentional."
                    ),
                    cwe="CWE-862",
                    file_path=rel_path,
                    line=line_no,
                ))

            # 检测 IDOR 风险
            for match in re.finditer(
                r'\.objects\.get\(\s*id\s*=',
                content
            ):
                line_no = content[:match.start()].count('\n') + 1
                if utils_is_ignored(rel_path, line_no,
                                    "business-idor", ignore_rules):
                    continue

                findings.append(Finding(
                    id="business-idor-risk",
                    dimension=ScanDimension.BUSINESS,
                    severity=Severity.MEDIUM,
                    title="Potential IDOR: object lookup by ID without ownership check",
                    description=(
                        "Object lookup by 'id' without ownership check. "
                        "This could allow users to access other users' data."
                    ),
                    cwe="CWE-639",
                    file_path=rel_path,
                    line=line_no,
                ))

            # 检测敏感信息被日志记录
            for match in re.finditer(
                r'logger\.\w+\([^)]*(?:password|passwd|token|secret|api_key)',
                content, re.IGNORECASE
            ):
                line_no = content[:match.start()].count('\n') + 1
                if utils_is_ignored(rel_path, line_no,
                                    "business-sensitive-logging", ignore_rules):
                    continue
                findings.append(Finding(
                    id="business-sensitive-logging",
                    dimension=ScanDimension.BUSINESS,
                    severity=Severity.HIGH,
                    title="Sensitive information logged",
                    description="日志中记录了密码/Token/密钥等敏感信息，会泄露到日志文件。",
                    cwe="CWE-532",
                    file_path=rel_path,
                    line=line_no,
                ))

            # 检测文件上传未做类型/大小校验
            for match in re.finditer(
                r'request\.FILES|request\.files|req\.files',
                content, re.IGNORECASE
            ):
                line_no = content[:match.start()].count('\n') + 1
                if utils_is_ignored(rel_path, line_no,
                                    "business-file-upload", ignore_rules):
                    continue
                # 检查上下文是否校验了文件类型/大小
                ctx_start = max(0, content.rfind('\n', 0, match.start()))
                ctx = content[ctx_start:match.end() + 300]
                if not re.search(
                    r'(content_type|file_type|extension|\.size|max_upload|MAX_SIZE|validate.*file)',
                    ctx, re.IGNORECASE
                ):
                    findings.append(Finding(
                        id="business-file-upload-unvalidated",
                        dimension=ScanDimension.BUSINESS,
                        severity=Severity.MEDIUM,
                        title="File upload without type/size validation",
                        description="文件上传未校验类型和大小，可能被用于上传恶意文件或造成 DoS。",
                        cwe="CWE-434",
                        file_path=rel_path,
                        line=line_no,
                    ))

            # 检测客户端可控金额（支付/订单）
            for match in re.finditer(
                r"(?:request\.data|request\.POST|request\.GET|req\.body|req\.query)"
                r"\[?\s*['\"]amount|['\"](?:amount|price|total)['\"]\s*[:=]\s*"
                r"(?:request\.data|request\.POST|request\.GET|req\.body)",
                content, re.IGNORECASE
            ):
                line_no = content[:match.start()].count('\n') + 1
                if utils_is_ignored(rel_path, line_no,
                                    "business-amount-controlled", ignore_rules):
                    continue
                findings.append(Finding(
                    id="business-amount-controlled",
                    dimension=ScanDimension.BUSINESS,
                    severity=Severity.HIGH,
                    title="Amount/price controlled by client",
                    description="金额或价格直接取自客户端请求，攻击者可以篡改交易金额。",
                    cwe="CWE-841",
                    file_path=rel_path,
                    line=line_no,
                ))

            # 检测堆栈信息泄露
            for match in re.finditer(
                r'(traceback\.print_exc|print_exc\(\)|Response\(.*traceback|"debug.*stack)',
                content, re.IGNORECASE
            ):
                line_no = content[:match.start()].count('\n') + 1
                if utils_is_ignored(rel_path, line_no,
                                    "business-stack-leak", ignore_rules):
                    continue
                findings.append(Finding(
                    id="business-stack-trace-leak",
                    dimension=ScanDimension.BUSINESS,
                    severity=Severity.MEDIUM,
                    title="Stack trace may be exposed to users",
                    description="异常处理可能向客户端暴露堆栈信息，泄露内部结构。",
                    cwe="CWE-209",
                    file_path=rel_path,
                    line=line_no,
                ))

    return findings


# =====================================================================
# 阶段 3: 聚合去重
# =====================================================================

def aggregate_findings(all_findings: list[list[Finding]],
                       ignore_rules: list[dict]) -> list[Finding]:
    """
    合并多个扫描结果，去重，排序。

    去重规则：相同 file_path + line (差 <= 3) + 相同漏洞类型
    """
    seen = set()
    unique = []

    for findings in all_findings:
        for f in findings:
            # 再次检查忽略规则
            if utils_is_ignored(
                f.file_path or "", f.line or 0, f.id, ignore_rules
            ):
                continue

            # 去重 key：全部维度按完整规则 id 区分。
            # 注意：不能用 (file, line) 折叠 config——缺失类检查都在 line 1，
            # 会把 CSRF/SSL/会话 Cookie 等不同问题误合并。
            key = (f.file_path, f.line or 0, f.dimension.value, f.id)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)

    # 排序：严重度（高→低），维度，文件路径
    severity_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
    }
    dim_order = {
        ScanDimension.CONFIG: 0, ScanDimension.DEPENDENCY: 1,
        ScanDimension.SAST: 2, ScanDimension.AUTH: 3,
        ScanDimension.BUSINESS: 4,
    }

    unique.sort(key=lambda f: (
        severity_order.get(f.severity, 99),
        dim_order.get(f.dimension, 99),
        f.file_path or "",
        f.line or 0,
    ))

    return unique


# =====================================================================
# 阶段 4: 报告输出
# =====================================================================

def generate_terminal_report(report: Report) -> str:
    """生成终端 Markdown 报告"""
    lines = []

    # 头部
    tech = report.tech_stack
    tech_str = " + ".join(
        [t.capitalize() if isinstance(t, str) else t
         for t in (tech.get("languages", []) + tech.get("frameworks", []))]
    ) or "Unknown"

    lines.append(f"""\
╔{'═' * 55}╗
║              🔒 Security Review Report                ║
╠{'═' * 55}╣
║  Project:    {report.project_name:<45}║
║  Tech Stack: {tech_str:<45}║
║  Duration:   {report.scan_time:<8.1f}s{' ' * 36}║
║  Dimensions: {', '.join(report.dimensions_covered):<45}║
╚{'═' * 55}╝
""")

    # 摘要表格
    lines.append("## 📊 扫描摘要\n")
    lines.append(report.summary_table())
    lines.append("")

    # 维度分布
    lines.append("### 维度分布\n")
    lines.append(report.dimension_table())
    lines.append("")

    # 详细发现
    lines.append("## 📋 详细发现\n")

    if not report.findings:
        lines.append("✅ 未发现安全问题。\n")
    else:
        for i, f in enumerate(report.findings, 1):
            file_loc = (
                f"`{f.file_path}:{f.line}`" if f.file_path else "N/A"
            )
            lines.append(f"""\
### {i}. {f.severity.emoji} [{f.severity.label}] {f.title}

**文件**: {file_loc}
**维度**: {f.dimension.label} | **CWE**: {f.cwe or '-'} | **OWASP**: {f.owasp or '-'}

**风险**: {f.description}
""")
            if f.attack_scenario:
                lines.append(f"**攻击场景**: {f.attack_scenario}\n")
            if f.code_snippet:
                lines.append(f"**代码**:\n```\n{f.code_snippet}\n```\n")
            if f.fixes:
                lines.append("**修复方案**:\n")
                for j, fix in enumerate(f.fixes, 1):
                    lines.append(
                        f"  {j}. {fix.description} [{fix.effort}]\n"
                    )
                    for op in fix.edit_operations:
                        lines.append(
                            f"     └→ `{op.file}`: {op.description}\n"
                        )
            lines.append("---\n")

    return "\n".join(lines)


def generate_json_report(report: Report) -> str:
    """生成 JSON 报告"""
    data = report.to_dict()
    data["metadata"]["generated_at"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )
    return json.dumps(data, indent=2, ensure_ascii=False)


def generate_markdown_report(report: Report) -> str:
    """生成 Markdown 报告（适合写入文件或 GitHub）"""
    lines = []

    tech = report.tech_stack
    tech_str = " + ".join(
        [t.capitalize() if isinstance(t, str) else t
         for t in (tech.get("languages", []) + tech.get("frameworks", []))]
    ) or "Unknown"

    lines.append(f"""# 🔒 Security Review Report

| 项目 | 技术栈 | 耗时 | 维度 |
|------|--------|------|------|
| {report.project_name} | {tech_str} | {report.scan_time:.1f}s | {', '.join(report.dimensions_covered)} |
""")

    # 摘要
    lines.append("## 📊 扫描摘要\n")
    lines.append(report.summary_table())
    lines.append("")
    lines.append("### 维度分布\n")
    lines.append(report.dimension_table())
    lines.append("")

    # 详细发现
    lines.append("## 📋 详细发现\n")

    if not report.findings:
        lines.append("✅ 未发现安全问题。\n")
    else:
        for i, f in enumerate(report.findings, 1):
            file_loc = (
                f"`{f.file_path}:{f.line}`" if f.file_path else "N/A"
            )
            lines.append(f"""\
### {i}. {f.severity.emoji} [{f.severity.label}] {f.title}

- **文件**: {file_loc}
- **维度**: {f.dimension.label}
- **CWE**: {f.cwe or '-'} | **OWASP**: {f.owasp or '-'}

**风险**: {f.description}
""")
            if f.attack_scenario:
                lines.append(f"**攻击场景**: {f.attack_scenario}\n")
            if f.code_snippet:
                lines.append(f"**代码**:\n```\n{f.code_snippet}\n```\n")
            if f.fixes:
                lines.append("**修复方案**:\n")
                for fix in f.fixes:
                    lines.append(f"- {fix.description} [{fix.effort}]")
                    for op in fix.edit_operations:
                        lines.append(
                            f"  - `{op.file}`: {op.description}"
                        )
            lines.append("")
            lines.append("---\n")

    return "\n".join(lines)


def generate_sarif_report(report: Report) -> str:
    """
    生成 SARIF 2.1.0 报告（GitHub Code Scanning / VS Code 原生支持）。

    严重度映射: critical/high → error, medium → warning, low/info → note
    """
    # 收集所有规则定义（去重）
    rules = {}
    for f in report.findings:
        rule_id = f.id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title[:200]},
                "fullDescription": {"text": f.description},
                "helpUri": "https://owasp.org/www-project-top-ten/",
                "properties": {
                    "cwe": f.cwe or "",
                    "owasp": f.owasp or "",
                    "dimension": f.dimension.value,
                },
            }

    def _level(sev: Severity) -> str:
        if sev in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if sev == Severity.MEDIUM:
            return "warning"
        return "note"

    results = []
    for f in report.findings:
        location = None
        if f.file_path:
            loc = {"artifactLocation": {"uri": f.file_path.replace("\\", "/")}}
            if f.line:
                loc["region"] = {"startLine": f.line}
            location = [{"physicalLocation": loc}]
        results.append({
            "ruleId": f.id,
            "level": _level(f.severity),
            "message": {
                "text": f"{f.title}\n{f.description}".strip()
            },
            "locations": location or [],
            "partialFingerprints": {
                "primaryLocationLineHash": f"{f.file_path or ''}:{f.line or 0}"
            },
            "properties": {
                "severity": f.severity.value,
                "auto_fixable": f.is_auto_fixable,
                "fixes": [fix.description for fix in f.fixes],
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                   "master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecurityReviewAgent",
                    "informationUri": "https://github.com/hubnsh/Security-Review-Agent",
                    "version": "2.1.1",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def interactive_fix(findings: list[Finding], root_path: str) -> int:
    """
    交互式修复（终端模式）。

    报告输出后提示用户输入编号 / all / q 选择要应用的修复。
    """
    auto = [(i, f) for i, f in enumerate(findings) if f.is_auto_fixable]
    if not auto:
        _safe_print("   (无可自动修复项)")
        return 0

    applied = 0
    while True:
        _safe_print(f"\n🛠 应用修复 — 共 {len(auto)} 项可自动修复\n")
        for idx, (_i, f) in enumerate(auto, 1):
            _safe_print(
                f"  [{idx}] {f.severity.emoji} [{f.severity.label}] {f.title}"
            )
        _safe_print(f"  [a] 全部 ({len(auto)} 项)  [q] 退出")

        try:
            choice = input(
                "请输入编号(逗号分隔), [a]全部, [q]退出 > "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            _safe_print("\n已退出")
            break

        if choice in ("q", "quit", "exit"):
            break

        if choice in ("a", "all"):
            selected = [f for _i, f in auto]
            applied = _apply_with_approval(selected, root_path)
            break

        indices = []
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(auto):
                    indices.append(auto[idx][1])
                else:
                    _safe_print(f"  ⚠️ 编号 {part} 超出范围")
        if not indices:
            _safe_print("  ⚠️ 无效输入，请输入编号或 a/q")
            continue
        applied = _apply_with_approval(indices, root_path)
        break

    return applied


def _apply_with_approval(selected: list[Finding], root_path: str) -> int:
    """
    应用选中的修复，含高危审批确认。

    存在 CRITICAL/HIGH 时提示用户确认；拒绝则仅应用 LOW/MEDIUM。
    """
    high = [f for f in selected
            if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    approve = False
    if high:
        _safe_print(f"\n⛔ 以下 {len(high)} 项为高危修复，需审批：")
        for f in high:
            _safe_print(f"     - [{f.severity.label}] {f.title} "
                        f"({f.file_path}:{f.line})")
        try:
            confirm = input("确认应用高危修复? (y/N) > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            confirm = "n"
        approve = confirm in ("y", "yes", "approve")

    return apply_fixes(selected, root_path, "all",
                       approve_high=approve)


def apply_fixes(findings: list[Finding], root_path: str,
                selection: str,
                approve_high: bool = False) -> int:
    """
    应用修复方案（批量）。

    企业级分级批准：CRITICAL/HIGH 的修复默认需要审批（approve_high=False
    时跳过并记入审计），LOW/MEDIUM 可直接应用。

    Args:
        findings: 已排序的 Finding 列表
        root_path: 项目根目录
        selection: 选择字符串（"all" 或 "1,3,5"，1 基索引对应报告编号）
        approve_high: 是否批准高危修复（默认 False）

    Returns:
        成功应用的 EditOperation 数量
    """
    if selection == "all":
        selected = list(range(len(findings)))
    else:
        selected = []
        for part in selection.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(findings):
                    selected.append(idx)
                else:
                    _safe_print(f"   ⚠️ 编号 {part} 超出范围，忽略",
                                file=sys.stderr)

    applied = 0
    for idx in selected:
        finding = findings[idx]

        # 分级批准：高危修复需审批
        if finding.severity in (Severity.CRITICAL, Severity.HIGH) \
                and not approve_high:
            _safe_print(
                f"   ⛔ [{finding.severity.label}] {finding.title} — "
                f"高危修复需审批（--approve 或交互确认）",
                file=sys.stderr,
            )
            _log_audit("fix_skipped_requires_approval", {
                "finding_id": finding.id,
                "dimension": finding.dimension.value,
                "severity": finding.severity.value,
                "file": finding.file_path,
                "title": finding.title,
            })
            continue

        # 每个 finding 只应用一个修复（多个 fix 是互斥的备选方案）
        for fix in finding.fixes:
            if not fix.edit_operations:
                continue
            fix_succeeded = False
            for op in fix.edit_operations:
                file_path = os.path.join(root_path, op.file)
                content = read_file_content(file_path)
                if content is None:
                    _safe_print(f"   ⚠️ 无法读取 {op.file}，跳过",
                                file=sys.stderr)
                    break
                if op.old_string and op.old_string in content:
                    try:
                        new_content = content.replace(
                            op.old_string, op.new_string, 1
                        )
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        _safe_print(f"   ✅ {op.file}: {op.description}",
                                    file=sys.stderr)
                        # 审计：记录每次修改
                        _log_audit("fix_applied", {
                            "finding_id": finding.id,
                            "dimension": finding.dimension.value,
                            "severity": finding.severity.value,
                            "file": op.file,
                            "description": op.description,
                            "old_len": len(op.old_string),
                            "new_len": len(op.new_string),
                            "new_string_preview": op.new_string[:80],
                        })
                        applied += 1
                        fix_succeeded = True
                    except (OSError, PermissionError) as e:
                        _safe_print(
                            f"   ❌ 写入失败 {op.file}: {e}",
                            file=sys.stderr,
                        )
                        break
                else:
                    _safe_print(
                        f"   ⚠️ 未找到匹配内容，跳过: {op.file} "
                        f"({op.description})",
                        file=sys.stderr,
                    )
                    break
            if fix_succeeded:
                # 该 finding 已修复，不再尝试其他备选方案
                break

    return applied


# =====================================================================
# CLI 入口
# =====================================================================

ALL_DIMENSIONS = ["config", "dependency", "sast", "auth", "business"]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="🔒 Security Review Agent — 多维安全扫描",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例:
  python engine.py
  python engine.py --quick
  python engine.py --focus config
  python engine.py --output json --no-fix
  python engine.py --output markdown
  python engine.py --diff HEAD~1
  python engine.py --apply all
  python engine.py --apply 1,3,5
  python engine.py --path /path/to/project
""",
    )
    parser.add_argument(
        "--path", "-p",
        default=os.getcwd(),
        help="项目路径（默认当前目录）",
    )
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="快速模式：仅配置 + 依赖扫描",
    )
    parser.add_argument(
        "--focus", "-f",
        choices=ALL_DIMENSIONS,
        help="聚焦单个扫描维度",
    )
    parser.add_argument(
        "--output", "-o",
        choices=["terminal", "json", "markdown", "sarif"],
        default="terminal",
        help="输出格式：terminal / json / markdown / sarif（默认 terminal）",
    )
    parser.add_argument(
        "--no-fix",
        action="store_true",
        help="不生成修复方案",
    )
    parser.add_argument(
        "--no-external",
        action="store_true",
        help="不调用外部工具（pip-audit/bandit），仅用内置引擎",
    )
    parser.add_argument(
        "--update-cve",
        action="store_true",
        help="从 OSV.dev 拉取最新 CVE 数据并写入缓存（.cve-cache.json）",
    )
    parser.add_argument(
        "--validate-rules",
        action="store_true",
        help="校验 rules/ 下所有 YAML 规则的结构",
    )
    parser.add_argument(
        "--apply",
        metavar="SELECTION",
        help="扫描后自动应用修复：'all' 或编号列表如 '1,3,5'（与报告编号对应）",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="批准高危（CRITICAL/HIGH）修复。默认仅应用 LOW/MEDIUM，高危需审批",
    )
    parser.add_argument(
        "--diff", "-d",
        metavar="REF",
        help="增量扫描：仅扫描与 REF 相比有变更的文件",
    )
    parser.add_argument(
        "--ignore-file",
        default="",
        help="忽略规则文件路径（默认项目根目录下的 .secreview-ignore）",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """主入口"""
    args = parse_args(argv)

    # 独立命令：校验规则
    if args.validate_rules:
        rules_dir = os.path.join(os.path.dirname(__file__), "rules")
        _safe_print(f"🔍 校验规则目录: {rules_dir}\n")
        count, error_count = validate_all_rules(rules_dir)
        _safe_print(f"\n📊 共 {count} 条规则，{error_count} 条出错")
        return 1 if error_count else 0

    # 独立命令：更新 CVE 缓存
    if args.update_cve:
        _safe_print("🔄 正在从 OSV.dev 拉取 CVE 数据...")
        from dependency_db import update_cve_cache
        try:
            stats = update_cve_cache()
        except Exception as e:
            _safe_print(f"❌ CVE 更新失败: {e}", file=sys.stderr)
            return 1
        _safe_print(f"✅ 更新 {stats['updated_packages']} 个包，"
                    f"共 {stats['total']} 条漏洞记录")
        _safe_print(f"   缓存文件: {stats.get('cache_file', '?')}")
        if stats["failed"]:
            _safe_print(f"   ⚠️ 失败 {len(stats['failed'])} 项: "
                        f"{stats['failed'][:5]}")
        return 0

    root_path = os.path.abspath(args.path)

    global USE_EXTERNAL_TOOLS
    USE_EXTERNAL_TOOLS = not args.no_external

    # 每次扫描开始时清空文件遍历缓存
    clear_glob_cache()

    if not os.path.isdir(root_path):
        _safe_print(f"❌ 路径不存在: {root_path}", file=sys.stderr)
        return 1

    start_time = time.time()

    # 进度消息辅助：非 terminal 模式（json/markdown）下进度走 stderr，
    # 保证 stdout 只有报告本体，便于 CI 管道解析。
    def progress(msg: str, **kw):
        if args.output != "terminal":
            kw["file"] = sys.stderr
        _safe_print(msg, **kw)

    # 加载忽略规则
    ignore_path = args.ignore_file or os.path.join(root_path, IGNORE_FILE)
    ignore_rules = load_ignore_rules(ignore_path)

    progress(f"🔍 Security Review: {root_path}")

    # Phase 1: 项目探针
    progress("📡 Phase 1/5: 项目探针...")
    probe = probe_project(root_path)
    progress(
        f"   → 语言: {', '.join(probe.languages) or 'N/A'} | "
        f"框架: {', '.join(probe.frameworks) or 'N/A'}"
    )

    # Phase 2: 扫描
    progress("🔬 Phase 2/5: 执行扫描...")

    # 增量模式：计算变更文件集合
    changed_files = None
    if args.diff:
        diff_files = compute_git_diff(args.diff, root_path)
        if diff_files:
            changed_files = {
                os.path.abspath(f) for f in diff_files if os.path.exists(f)
            }
            progress(f"   → 增量模式: {len(changed_files)} 个变更文件")
        else:
            progress("   ⚠️ 无法获取变更文件（git diff 失败），回退全量扫描")

    # 确定启用的维度
    if args.focus:
        active_dims = [args.focus]
    elif args.quick:
        active_dims = ["config", "dependency"]
    else:
        active_dims = ALL_DIMENSIONS[:]

    # 审计：扫描开始（记录版本元数据）
    rules_dir = os.path.join(os.path.dirname(__file__), "rules")
    _log_audit("scan_start", {
        "project": root_path,
        "git_commit": _get_git_commit(root_path),
        "rules_version": _get_rules_version(rules_dir),
        "dimensions": active_dims,
        "diff": args.diff or None,
        "external_tools": USE_EXTERNAL_TOOLS,
    })

    scanner_map = {
        "config": ("⚙️  配置安全", scan_config),
        "dependency": ("📦 依赖漏洞", scan_dependencies),
        "sast": ("🔎 代码安全 (SAST)", scan_sast),
        "auth": ("🔑 认证授权", scan_auth),
        "business": ("💼 业务逻辑", scan_business),
    }

    # 并行执行扫描器（I/O + 正则，线程池即可提速）
    from concurrent.futures import ThreadPoolExecutor, as_completed
    all_findings = []
    active = [d for d in active_dims if d in scanner_map]
    with ThreadPoolExecutor(max_workers=min(len(active), 5)) as executor:
        futures = {}
        for dim in active:
            label, scanner_fn = scanner_map[dim]
            progress(f"   - {label}...", end="", flush=True)
            fut = executor.submit(
                scanner_fn, probe, root_path, ignore_rules, changed_files
            )
            futures[fut] = (dim, label)

        for fut in as_completed(futures):
            dim, label = futures[fut]
            try:
                results = fut.result()
                all_findings.append(results)
                progress(f"   ✓ {label}: {len(results)} 项发现")
            except Exception as e:
                progress(f"   ❌ {label}: {e}")

    # Phase 3: 聚合去重
    progress("🔄 Phase 3/5: 聚合去重...")
    findings = aggregate_findings(all_findings, ignore_rules)
    progress(f"   → 去重后: {len(findings)} 项发现")

    # 审计：扫描完成（记录结果统计 + 版本元数据，供复现）
    rules_dir = os.path.join(os.path.dirname(__file__), "rules")
    _log_audit("scan_complete", {
        "project": root_path,
        "git_commit": _get_git_commit(root_path),
        "rules_version": _get_rules_version(rules_dir),
        "dimensions": active_dims,
        "findings_total": sum(len(x) for x in all_findings),
        "findings_after_dedup": len(findings),
    })

    # Phase 4: 修复方案已在扫描阶段生成（在 Finding.fixes 中）

    # Phase 5: 输出报告
    scan_time = time.time() - start_time
    progress(f"📊 Phase 5/5: 生成报告 ({scan_time:.1f}s)\n")

    report = Report(
        project_name=Path(root_path).name,
        tech_stack={
            "languages": probe.languages,
            "frameworks": probe.frameworks,
            "dep_managers": probe.dep_managers,
        },
        scan_time=scan_time,
        dimensions_covered=active_dims,
        findings=findings,
    )

    if args.output == "json":
        output = generate_json_report(report)
    elif args.output == "markdown":
        output = generate_markdown_report(report)
    elif args.output == "sarif":
        output = generate_sarif_report(report)
    else:
        output = generate_terminal_report(report)

    # 报告输出（自动兼容终端编码）
    try:
        sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
    except (AttributeError, BrokenPipeError):
        _safe_print(output)

    # 应用修复：批处理（--apply）或交互式（终端 TTY）
    if args.apply and not args.no_fix:
        progress("\n🛠 应用修复...")
        n = apply_fixes(findings, root_path, args.apply,
                        approve_high=args.approve)
        progress(f"\n✅ 已应用 {n} 个修复操作")
        if n == 0:
            progress("   (提示: 无匹配的修复操作，可能已修复或选择编号无效)")
    elif (args.output == "terminal" and not args.no_fix
          and sys.stdin.isatty()):
        interactive_fix(findings, root_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
