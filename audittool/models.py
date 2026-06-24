"""
Data models for audit findings.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import json


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    GAS = "gas"
    UNKNOWN = "unknown"


class Status(str, Enum):
    FIXED = "fixed"
    ACKNOWLEDGED = "acknowledged"
    WONT_FIX = "wont-fix"
    PARTIALLY_FIXED = "partially-fixed"
    MITIGATED = "mitigated"
    DISPUTED = "disputed"
    UNKNOWN = "unknown"


class ReportFormat(str, Enum):
    PDF = "pdf"
    MARKDOWN = "markdown"
    HTML = "html"
    TEXT = "text"
    UNKNOWN = "unknown"


@dataclass
class CodeSnippet:
    """A code snippet with optional context."""
    code: str = ""
    language: str = "solidity"
    file_ref: str = ""          # e.g. "Bridge.sol#L42"
    description: str = ""       # what this snippet shows

    def to_dict(self):
        return asdict(self)


@dataclass
class Finding:
    """A single vulnerability finding extracted from an audit report."""

    # ── Identity ────────────────────────────────────────────────────────────
    finding_id: str = ""          # e.g. "H-01", "TOB-XX-3", "C-02"
    title: str = ""               # Full title of the finding

    # ── Classification ──────────────────────────────────────────────────────
    severity: Severity = Severity.UNKNOWN
    status: Status = Status.UNKNOWN
    finding_type: str = ""        # e.g. "Reentrancy", "Access Control", "Logic"
    tags: list[str] = field(default_factory=list)  # auto-detected vulnerability tags

    # ── Full Description ────────────────────────────────────────────────────
    description: str = ""         # Full problem description (nothing omitted)
    root_cause: str = ""          # Why does this bug exist?
    impact: str = ""              # What damage can it cause?
    likelihood: str = ""          # How easy is it to exploit?

    # ── Location ────────────────────────────────────────────────────────────
    affected_contracts: list[str] = field(default_factory=list)   # ["Bridge.sol"]
    affected_functions: list[str] = field(default_factory=list)   # ["withdrawFunds()"]
    affected_lines: list[str] = field(default_factory=list)       # ["Bridge.sol#L42-L55"]

    # ── Code Evidence ───────────────────────────────────────────────────────
    vulnerable_code: list[CodeSnippet] = field(default_factory=list)
    proof_of_concept: str = ""    # Attack scenario / PoC
    attack_scenario: str = ""     # Step-by-step exploit

    # ── Fix ─────────────────────────────────────────────────────────────────
    recommendation: str = ""      # Full recommendation text
    fixed_code: list[CodeSnippet] = field(default_factory=list)
    fix_description: str = ""     # Summary of how it was fixed
    fix_diff: str = ""            # Unified diff if available

    # ── AI Audit Checklist ──────────────────────────────────────────────────
    # Generated from the finding — what to check in new code
    check_points: list[str] = field(default_factory=list)

    # ── Source ──────────────────────────────────────────────────────────────
    source_report: str = ""       # Report filename
    auditor: str = ""             # Auditing firm name
    report_date: str = ""         # When the audit was done
    report_version: str = ""      # Contract version audited
    raw_section: str = ""         # Original raw text extracted

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d

    def __repr__(self):
        return f"Finding({self.finding_id!r}, {self.severity.value}, {self.title[:60]!r})"


@dataclass
class AuditReport:
    """Full parsed audit report."""

    # ── Report Metadata ─────────────────────────────────────────────────────
    source_file: str = ""
    report_format: ReportFormat = ReportFormat.UNKNOWN
    auditor: str = ""
    project_name: str = ""
    report_date: str = ""
    report_version: str = ""      # Version of contracts audited
    scope: list[str] = field(default_factory=list)       # in-scope contracts
    out_of_scope: list[str] = field(default_factory=list)

    # ── Findings ─────────────────────────────────────────────────────────────
    findings: list[Finding] = field(default_factory=list)

    # ── Summary Stats ────────────────────────────────────────────────────────
    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return {k: v for k, v in counts.items() if v > 0}

    @property
    def by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Status}
        for f in self.findings:
            counts[f.status.value] += 1
        return {k: v for k, v in counts.items() if v > 0}

    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "report_format": self.report_format.value,
            "auditor": self.auditor,
            "project_name": self.project_name,
            "report_date": self.report_date,
            "report_version": self.report_version,
            "scope": self.scope,
            "out_of_scope": self.out_of_scope,
            "summary": {
                "total_findings": self.total_findings,
                "by_severity": self.by_severity,
                "by_status": self.by_status,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AggregatedDatabase:
    """Aggregated findings from multiple audit reports."""

    reports: list[AuditReport] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)

    @property
    def total_reports(self) -> int:
        return len(self.reports)

    @property
    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.all_findings:
            result[f.severity.value].append(f)
        return {k: v for k, v in result.items() if v}

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_reports": self.total_reports,
                "total_findings": len(self.all_findings),
                "by_severity": {k: len(v) for k, v in self.by_severity.items()},
            },
            "reports": [r.to_dict() for r in self.reports],
            "all_findings": [f.to_dict() for f in self.all_findings],
        }
