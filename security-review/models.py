"""
Security Review Agent — 数据模型

核心数据类：Finding、Fix、EditOperation、Report、ProbeResult
枚举：Severity、ScanDimension
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any


class Severity(str, Enum):
    """漏洞严重度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
        return order.index(self) < order.index(other)

    @property
    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "⚪",
        }[self]

    @property
    def label(self) -> str:
        return {
            Severity.CRITICAL: "CRITICAL",
            Severity.HIGH: "HIGH",
            Severity.MEDIUM: "MEDIUM",
            Severity.LOW: "LOW",
            Severity.INFO: "INFO",
        }[self]


class ScanDimension(str, Enum):
    """扫描维度"""
    DEPENDENCY = "dependency"
    CONFIG = "config"
    SAST = "sast"
    AUTH = "auth"
    BUSINESS = "business"

    @property
    def label(self) -> str:
        return {
            ScanDimension.DEPENDENCY: "Dependency CVE",
            ScanDimension.CONFIG: "Config Security",
            ScanDimension.SAST: "SAST Injection",
            ScanDimension.AUTH: "Auth & Access Control",
            ScanDimension.BUSINESS: "Business Logic",
        }[self]


@dataclass
class EditOperation:
    """对单个文件的编辑操作"""
    file: str
    old_string: str
    new_string: str
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "old_string": self.old_string,
            "new_string": self.new_string,
            "description": self.description,
        }


@dataclass
class Fix:
    """修复方案"""
    description: str
    type: str  # "env_var" | "edit" | "config" | "architectural"
    effort: str = "medium"  # "low" | "medium" | "high"
    edit_operations: list[EditOperation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "type": self.type,
            "effort": self.effort,
            "edit_operations": [op.to_dict() for op in self.edit_operations],
        }


@dataclass
class Finding:
    """单个安全发现"""
    id: str
    dimension: ScanDimension
    severity: Severity
    title: str
    description: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    attack_scenario: Optional[str] = None
    fixes: list[Fix] = field(default_factory=list)

    @property
    def is_auto_fixable(self) -> bool:
        """是否有自动修复方案"""
        return any(f.type in ("edit", "config", "env_var") for f in self.fixes)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "dimension": self.dimension.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "file_path": self.file_path,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "attack_scenario": self.attack_scenario,
            "auto_fixable": self.is_auto_fixable,
            "fixes": [f.to_dict() for f in self.fixes],
        }


@dataclass
class Report:
    """完整扫描报告"""
    project_name: str
    tech_stack: dict[str, Any]
    scan_time: float
    dimensions_covered: list[str]
    findings: list[Finding]

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def auto_fixable(self) -> int:
        return sum(1 for f in self.findings if f.is_auto_fixable)

    def to_dict(self) -> dict:
        return {
            "metadata": {
                "project_name": self.project_name,
                "tech_stack": self.tech_stack,
                "scan_time_seconds": self.scan_time,
                "dimensions_covered": self.dimensions_covered,
                "generated_at": None,  # 由调用方填充
            },
            "summary": {
                "total": self.total,
                "critical": self.critical,
                "high": self.high,
                "medium": self.medium,
                "low": self.low,
                "auto_fixable": self.auto_fixable,
            },
            "findings": [f.to_dict() for f in sorted(
                self.findings,
                key=lambda x: (x.severity, x.id),
            )],
        }

    def summary_table(self) -> str:
        """生成 Markdown 摘要表格"""
        lines = [
            "| 严重度 | 数量 | 可自动修复 |",
            "|--------|------|-----------|",
            f"| 🔴 Critical | {self.critical} | {sum(1 for f in self.findings if f.severity == Severity.CRITICAL and f.is_auto_fixable)} |",
            f"| 🟠 High     | {self.high} | {sum(1 for f in self.findings if f.severity == Severity.HIGH and f.is_auto_fixable)} |",
            f"| 🟡 Medium   | {self.medium} | {sum(1 for f in self.findings if f.severity == Severity.MEDIUM and f.is_auto_fixable)} |",
            f"| 🟢 Low      | {self.low} | {sum(1 for f in self.findings if f.severity == Severity.LOW and f.is_auto_fixable)} |",
            f"| **合计**    | **{self.total}** | **{self.auto_fixable}** |",
        ]
        return "\n".join(lines)

    def dimension_table(self) -> str:
        """生成维度分布表格"""
        dims = {}
        for d in ScanDimension:
            found = [f for f in self.findings if f.dimension == d]
            if found:
                c = sum(1 for f in found if f.severity == Severity.CRITICAL)
                rest = len(found) - c
                dims[d.label] = (c, rest, len(found))

        lines = ["| 扫描维度 | 🔴 | 🟠🟡🟢 | 合计 |",
                 "|----------|----|--------|------|"]
        for label in (d.label for d in ScanDimension):
            if label in dims:
                c, rest, total = dims[label]
                lines.append(f"| {label} | {c} | {rest} | {total} |")
        return "\n".join(lines)


@dataclass
class ProbeResult:
    """项目探针结果"""
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    dep_managers: list[str] = field(default_factory=list)
    has_dockerfile: bool = False
    has_cicd: bool = False
    config_files: dict[str, str] = field(default_factory=dict)
    file_stats: dict[str, int] = field(default_factory=dict)
    rules_to_load: list[str] = field(default_factory=list)

    @property
    def tech_stack_label(self) -> str:
        parts = []
        if self.languages:
            parts.append(" + ".join(l.capitalize() for l in self.languages[:3]))
        if self.frameworks:
            parts.append(" + ".join(f.capitalize() for f in self.frameworks[:3]))
        return " ".join(parts) if parts else "Unknown"

    def to_dict(self) -> dict:
        return {
            "languages": self.languages,
            "frameworks": self.frameworks,
            "dep_managers": self.dep_managers,
            "has_dockerfile": self.has_dockerfile,
            "has_cicd": self.has_cicd,
            "config_files": self.config_files,
            "file_stats": self.file_stats,
            "rules_to_load": self.rules_to_load,
        }
