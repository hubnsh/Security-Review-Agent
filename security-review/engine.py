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
)
from dependency_db import (
    check_python_package, check_npm_package,
    check_go_package, check_java_package,
    format_vulnerability,
)
from sast_patterns import match_in_content, get_all_vuln_types


# =====================================================================
# 内置忽略规则默认路径
# =====================================================================
IGNORE_FILE = ".secreview-ignore"


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
    """扫描 Python 依赖"""
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

                results = match_in_content(content, lang)
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

    基于启发式规则检测常见认证配置缺陷。
    """
    findings = []

    if "django" in probe.frameworks:
        # 检查 settings.py 中的认证配置
        settings_files = glob_files(root_path, "**/settings.py")
        for sf in settings_files:
            if changed_files is not None and os.path.abspath(sf) not in changed_files:
                continue
            rel_path = os.path.relpath(sf, root_path).replace("\\", "/")
            content = read_file_content(sf)
            if not content:
                continue

            # 检查 SESSION_COOKIE_SECURE
            if "SESSION_COOKIE_SECURE" not in content:
                finding = Finding(
                    id="auth-django-session-cookie-secure",
                    dimension=ScanDimension.AUTH,
                    severity=Severity.MEDIUM,
                    title="Session Cookie Secure flag not set",
                    description=(
                        "SESSION_COOKIE_SECURE is not configured. "
                        "Session cookie will be sent over HTTP connections."
                    ),
                    cwe="CWE-614",
                    file_path=rel_path,
                    line=1,
                    fixes=[
                        Fix(
                            description="Add SESSION_COOKIE_SECURE=True",
                            type="config",
                            effort="low",
                            edit_operations=[
                                EditOperation(
                                    file=rel_path,
                                    old_string="",
                                    new_string=(
                                        "SESSION_COOKIE_SECURE = True\n"
                                        "SESSION_COOKIE_HTTPONLY = True\n"
                                        "SESSION_COOKIE_SAMESITE = 'Lax'\n"
                                    ),
                                    description="Add secure session cookie settings",
                                )
                            ],
                        )
                    ],
                )
                if not utils_is_ignored(rel_path, 0, finding.id, ignore_rules):
                    findings.append(finding)

            # 检查 DEFAULT_AUTHENTICATION_CLASSES
            if ("DEFAULT_AUTHENTICATION_CLASSES" not in content
                    and "REST_FRAMEWORK" in content):
                finding = Finding(
                    id="auth-django-default-auth-classes",
                    dimension=ScanDimension.AUTH,
                    severity=Severity.MEDIUM,
                    title="Default authentication classes not configured",
                    description=(
                        "REST Framework is configured but "
                        "DEFAULT_AUTHENTICATION_CLASSES is not set."
                    ),
                    cwe="CWE-287",
                    file_path=rel_path,
                    line=1,
                )
                if not utils_is_ignored(rel_path, 0, finding.id, ignore_rules):
                    findings.append(finding)

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

            # 去重 key
            key = (f.file_path, f.line or 0, f.id.split("-")[0])
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


def apply_fixes(findings: list[Finding], root_path: str,
                selection: str) -> int:
    """
    应用修复方案（批量）。

    Args:
        findings: 已排序的 Finding 列表
        root_path: 项目根目录
        selection: 选择字符串（"all" 或 "1,3,5"，1 基索引对应报告编号）

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
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="输出格式：terminal / json / markdown（默认 terminal）",
    )
    parser.add_argument(
        "--no-fix",
        action="store_true",
        help="不生成修复方案",
    )
    parser.add_argument(
        "--apply",
        metavar="SELECTION",
        help="扫描后自动应用修复：'all' 或编号列表如 '1,3,5'（与报告编号对应）",
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
    root_path = os.path.abspath(args.path)

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

    scanner_map = {
        "config": ("⚙️  配置安全", scan_config),
        "dependency": ("📦 依赖漏洞", scan_dependencies),
        "sast": ("🔎 代码安全 (SAST)", scan_sast),
        "auth": ("🔑 认证授权", scan_auth),
        "business": ("💼 业务逻辑", scan_business),
    }

    all_findings = []
    for dim in active_dims:
        if dim not in scanner_map:
            continue
        label, scanner_fn = scanner_map[dim]
        progress(f"   - {label}...", end="", flush=True)
        try:
            findings = scanner_fn(probe, root_path, ignore_rules,
                                  changed_files)
            all_findings.append(findings)
            progress(f" {len(findings)} 项发现")
        except Exception as e:
            progress(f" ❌ 错误: {e}")

    # Phase 3: 聚合去重
    progress("🔄 Phase 3/5: 聚合去重...")
    findings = aggregate_findings(all_findings, ignore_rules)
    progress(f"   → 去重后: {len(findings)} 项发现")

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
    else:
        output = generate_terminal_report(report)

    # 报告输出（自动兼容终端编码）
    try:
        sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
    except (AttributeError, BrokenPipeError):
        _safe_print(output)

    # 应用修复
    if args.apply and not args.no_fix:
        progress("\n🛠 应用修复...")
        n = apply_fixes(findings, root_path, args.apply)
        progress(f"\n✅ 已应用 {n} 个修复操作")
        if n == 0:
            progress("   (提示: 无匹配的修复操作，可能已修复或选择编号无效)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
