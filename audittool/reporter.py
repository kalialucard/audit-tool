"""
Reporter — generates comprehensive Markdown and terminal reports.
Outputs a full detailed report: every finding, every field, nothing omitted.
"""

from __future__ import annotations
import json
import textwrap
from pathlib import Path
from datetime import datetime
from typing import Optional

from audittool.models import (
    AuditReport, AggregatedDatabase, Finding, Severity, Status
)


# ─── ANSI Colors for Terminal ──────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"
    BG_RED = "\033[41m"


SEVERITY_COLORS = {
    Severity.CRITICAL:      (C.BG_RED + C.WHITE + C.BOLD, "🔴 CRITICAL"),
    Severity.HIGH:          (C.RED + C.BOLD,               "🟠 HIGH"),
    Severity.MEDIUM:        (C.YELLOW + C.BOLD,            "🟡 MEDIUM"),
    Severity.LOW:           (C.CYAN + C.BOLD,              "🔵 LOW"),
    Severity.INFORMATIONAL: (C.GRAY + C.BOLD,              "⚪ INFO"),
    Severity.GAS:           (C.GREEN + C.BOLD,             "⛽ GAS"),
    Severity.UNKNOWN:       (C.WHITE,                      "❓ UNKNOWN"),
}

SEVERITY_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡",
    "low": "🔵", "informational": "⚪", "gas": "⛽", "unknown": "❓",
}

STATUS_EMOJI = {
    "fixed": "✅", "acknowledged": "📝", "wont-fix": "❌",
    "partially-fixed": "🔧", "mitigated": "🛡️", "disputed": "⚖️", "unknown": "❓",
}


# ─── Terminal Output ───────────────────────────────────────────────────────────

def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
 █████╗ ██╗   ██╗██████╗ ██╗████████╗    ████████╗ ██████╗  ██████╗ ██╗
██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝       ██╔══╝██╔═══██╗██╔═══██╗██║
███████║██║   ██║██║  ██║██║   ██║          ██║   ██║   ██║██║   ██║██║
██╔══██║██║   ██║██║  ██║██║   ██║          ██║   ██║   ██║██║   ██║██║
██║  ██║╚██████╔╝██████╔╝██║   ██║          ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{C.RESET}{C.GRAY}  Smart Contract Audit Report Extractor — No AI Required{C.RESET}
""")


def _sev_label(severity: Severity) -> str:
    color, label = SEVERITY_COLORS.get(severity, (C.WHITE, str(severity.value).upper()))
    return f"{color}{label}{C.RESET}"


def _wrap(text: str, width: int = 90, indent: str = "    ") -> str:
    if not text:
        return ""
    lines = text.split("\n")
    wrapped = []
    for line in lines:
        if len(line) > width:
            wrapped.extend(
                textwrap.wrap(line, width=width, subsequent_indent=indent)
            )
        else:
            wrapped.append(line)
    return "\n".join(indent + l for l in wrapped)


def print_report_summary(report: AuditReport) -> None:
    """Print a single report's summary to terminal."""
    print(f"\n{C.BOLD}{C.BLUE}{'═' * 80}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  📋 REPORT: {report.source_file}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'═' * 80}{C.RESET}")
    print(f"  {C.BOLD}Format   :{C.RESET} {report.report_format.value.upper()}")
    print(f"  {C.BOLD}Auditor  :{C.RESET} {report.auditor or 'Unknown'}")
    print(f"  {C.BOLD}Project  :{C.RESET} {report.project_name or 'Unknown'}")
    print(f"  {C.BOLD}Date     :{C.RESET} {report.report_date or 'Unknown'}")
    print(f"  {C.BOLD}Version  :{C.RESET} {report.report_version or 'Unknown'}")
    if report.scope:
        print(f"  {C.BOLD}Scope    :{C.RESET} {', '.join(report.scope[:5])}{'...' if len(report.scope) > 5 else ''}")

    print(f"\n  {C.BOLD}Findings Summary:{C.RESET}")
    for sev, count in report.by_severity.items():
        color, label = SEVERITY_COLORS.get(Severity(sev), (C.WHITE, sev.upper()))
        bar = "█" * min(count, 40)
        print(f"    {color}{label:<22}{C.RESET} {count:>3}  {C.GRAY}{bar}{C.RESET}")

    print(f"\n  {C.BOLD}Total:{C.RESET} {report.total_findings} findings")


def print_finding(finding: Finding, index: int, total: int) -> None:
    """Print a single finding with full detail to terminal."""
    sev_color, sev_label = SEVERITY_COLORS.get(finding.severity, (C.WHITE, "UNKNOWN"))
    status_emoji = STATUS_EMOJI.get(finding.status.value, "❓")

    print(f"\n{C.GRAY}{'─' * 80}{C.RESET}")
    print(
        f"  {C.BOLD}Finding {index}/{total}{C.RESET}  "
        f"{sev_color}[{sev_label}]{C.RESET}  "
        f"{C.BOLD}{finding.finding_id or 'No-ID'}{C.RESET}  "
        f"{status_emoji} {finding.status.value.upper()}"
    )
    print(f"\n  {C.BOLD}{C.WHITE}{finding.title or '(No title)'}{C.RESET}")

    if finding.finding_type:
        print(f"  {C.GRAY}Type: {finding.finding_type}{C.RESET}")
    if finding.tags:
        print(f"  {C.GRAY}Tags: {', '.join(finding.tags)}{C.RESET}")

    # Description
    if finding.description:
        print(f"\n  {C.BOLD}📄 Description:{C.RESET}")
        print(_wrap(finding.description))

    # Root Cause
    if finding.root_cause:
        print(f"\n  {C.BOLD}🔍 Root Cause:{C.RESET}")
        print(_wrap(finding.root_cause))

    # Impact
    if finding.impact:
        print(f"\n  {C.BOLD}💥 Impact:{C.RESET}")
        print(_wrap(finding.impact))

    # Likelihood
    if finding.likelihood:
        print(f"\n  {C.BOLD}📊 Likelihood / Difficulty:{C.RESET}")
        print(_wrap(finding.likelihood))

    # Affected Locations
    if finding.affected_contracts or finding.affected_functions or finding.affected_lines:
        print(f"\n  {C.BOLD}📍 Affected Locations:{C.RESET}")
        if finding.affected_contracts:
            print(f"    Contracts: {', '.join(finding.affected_contracts[:8])}")
        if finding.affected_functions:
            print(f"    Functions: {', '.join(finding.affected_functions[:8])}")
        if finding.affected_lines:
            print(f"    Lines:     {', '.join(finding.affected_lines[:8])}")

    # Vulnerable Code
    if finding.vulnerable_code:
        print(f"\n  {C.BOLD}⚠️  Vulnerable Code:{C.RESET}")
        for snippet in finding.vulnerable_code:
            _print_code_block(snippet.code, snippet.language, color=C.RED)

    # Proof of Concept
    if finding.proof_of_concept:
        print(f"\n  {C.BOLD}🧪 Proof of Concept / Attack Scenario:{C.RESET}")
        print(_wrap(finding.proof_of_concept))

    if finding.attack_scenario and finding.attack_scenario != finding.proof_of_concept:
        print(_wrap(finding.attack_scenario))

    # Recommendation
    if finding.recommendation:
        print(f"\n  {C.BOLD}✅ Recommendation:{C.RESET}")
        print(_wrap(finding.recommendation))

    # Fixed Code
    if finding.fixed_code:
        print(f"\n  {C.BOLD}🔧 Fixed Code:{C.RESET}")
        for snippet in finding.fixed_code:
            _print_code_block(snippet.code, snippet.language, color=C.GREEN)

    # Fix Description
    if finding.fix_description:
        print(f"\n  {C.BOLD}📝 Fix Applied:{C.RESET}")
        print(_wrap(finding.fix_description))

    # AI Check Points
    if finding.check_points:
        print(f"\n  {C.BOLD}🎯 What to Check in New Code:{C.RESET}")
        for cp in finding.check_points:
            print(f"    • {cp}")

    # Source
    print(f"\n  {C.GRAY}Source: {finding.source_report} | Auditor: {finding.auditor} | Date: {finding.report_date}{C.RESET}")


def _print_code_block(code: str, lang: str = "solidity", color: str = "") -> None:
    """Print a code block with syntax-aware coloring."""
    lines = code.split("\n")
    print(f"    {C.GRAY}┌─ {lang} {'─' * 50}{C.RESET}")
    for line in lines:
        print(f"    {C.GRAY}│{C.RESET} {color}{line}{C.RESET}")
    print(f"    {C.GRAY}└{'─' * 53}{C.RESET}")


def print_aggregated_summary(db: AggregatedDatabase) -> None:
    """Print full aggregated summary for multiple reports."""
    print(f"\n{C.BOLD}{C.MAGENTA}{'═' * 80}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  🗂  AGGREGATED REPORT SUMMARY{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}{'═' * 80}{C.RESET}")
    print(f"\n  {C.BOLD}Total Reports  :{C.RESET} {db.total_reports}")
    print(f"  {C.BOLD}Total Findings :{C.RESET} {len(db.all_findings)}")

    print(f"\n  {C.BOLD}By Severity:{C.RESET}")
    for sev, findings in db.by_severity.items():
        color, label = SEVERITY_COLORS.get(Severity(sev), (C.WHITE, sev.upper()))
        bar = "█" * min(len(findings), 50)
        print(f"    {color}{label:<22}{C.RESET} {len(findings):>4}  {C.GRAY}{bar}{C.RESET}")

    # Top auditors
    auditor_counts: dict[str, int] = {}
    for r in db.reports:
        key = r.auditor or "Unknown"
        auditor_counts[key] = auditor_counts.get(key, 0) + r.total_findings
    if auditor_counts:
        print(f"\n  {C.BOLD}By Auditor:{C.RESET}")
        for auditor, count in sorted(auditor_counts.items(), key=lambda x: -x[1]):
            print(f"    {C.GRAY}•{C.RESET} {auditor:<30} {count} findings")

    # Top tags
    tag_counts: dict[str, int] = {}
    for f in db.all_findings:
        for tag in f.tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    if tag_counts:
        print(f"\n  {C.BOLD}Top Vulnerability Types:{C.RESET}")
        for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1])[:15]:
            bar = "█" * min(count, 30)
            print(f"    {C.CYAN}{tag:<30}{C.RESET} {count:>3}  {C.GRAY}{bar}{C.RESET}")


# ─── Markdown Report Generator ────────────────────────────────────────────────

def generate_markdown_report(
    report: AuditReport,
    output_path: Optional[Path] = None,
    include_raw: bool = False,
) -> str:
    """
    Generate a complete, detailed Markdown report for a single audit report.
    Nothing is omitted — every field is included.
    """
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        f"# 📋 Audit Report Analysis",
        f"",
        f"> Generated by AuditTool on {now}",
        f"",
        f"---",
        f"",
        f"## 📁 Report Information",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Source File** | `{report.source_file}` |",
        f"| **Format** | {report.report_format.value.upper()} |",
        f"| **Auditor** | {report.auditor or 'Unknown'} |",
        f"| **Project** | {report.project_name or 'Unknown'} |",
        f"| **Audit Date** | {report.report_date or 'Unknown'} |",
        f"| **Version Audited** | {report.report_version or 'Unknown'} |",
        f"| **Total Findings** | **{report.total_findings}** |",
        f"",
    ]

    if report.scope:
        lines += [
            f"### 🎯 Scope",
            f"",
            *[f"- `{s}`" for s in report.scope],
            f"",
        ]

    if report.out_of_scope:
        lines += [
            f"### 🚫 Out of Scope",
            f"",
            *[f"- `{s}`" for s in report.out_of_scope],
            f"",
        ]

    # ── Summary Table ─────────────────────────────────────────────────────────
    lines += [
        f"---",
        f"",
        f"## 📊 Findings Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev, count in report.by_severity.items():
        emoji = SEVERITY_EMOJI.get(sev, "❓")
        lines.append(f"| {emoji} **{sev.upper()}** | {count} |")
    lines += [
        f"| **TOTAL** | **{report.total_findings}** |",
        f"",
    ]

    # Status summary
    if report.by_status:
        lines += [
            f"| Status | Count |",
            f"|--------|-------|",
        ]
        for status, count in report.by_status.items():
            emoji = STATUS_EMOJI.get(status, "❓")
            lines.append(f"| {emoji} {status.upper()} | {count} |")
        lines.append("")

    # ── Table of Contents ─────────────────────────────────────────────────────
    lines += [
        f"---",
        f"",
        f"## 📑 Table of Contents",
        f"",
    ]
    for i, finding in enumerate(report.findings, 1):
        sev_emoji = SEVERITY_EMOJI.get(finding.severity.value, "❓")
        anchor = _make_anchor(f"{i}-{finding.finding_id}-{finding.title}")
        lines.append(
            f"{i}. [{sev_emoji} [{finding.severity.value.upper()}] "
            f"`{finding.finding_id}` — {finding.title}](#{anchor})"
        )
    lines += ["", "---", ""]

    # ── Individual Findings ───────────────────────────────────────────────────
    lines += [
        f"## 🔍 Detailed Findings",
        f"",
    ]

    for i, finding in enumerate(report.findings, 1):
        lines += _finding_to_markdown(finding, i, len(report.findings), include_raw)

    # ── Footer ────────────────────────────────────────────────────────────────
    lines += [
        f"---",
        f"",
        f"*Report generated by AuditTool — Smart Contract Audit Extractor*",
        f"*{now}*",
    ]

    content = "\n".join(lines)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

    return content


def _finding_to_markdown(
    finding: Finding, index: int, total: int, include_raw: bool = False
) -> list[str]:
    """Convert a Finding to detailed Markdown lines."""
    lines: list[str] = []
    sev_emoji = SEVERITY_EMOJI.get(finding.severity.value, "❓")
    status_emoji = STATUS_EMOJI.get(finding.status.value, "❓")

    title_str = finding.title or "(No title)"
    id_str = finding.finding_id or f"F-{index:03d}"
    anchor_id = _make_anchor(f"{index}-{id_str}-{title_str}")

    lines += [
        f"<a name=\"{anchor_id}\"></a>",
        f"",
        f"### {index}. {sev_emoji} `{id_str}` — {title_str}",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Severity** | {sev_emoji} **{finding.severity.value.upper()}** |",
        f"| **Status** | {status_emoji} {finding.status.value.upper()} |",
        f"| **ID** | `{id_str}` |",
    ]
    if finding.finding_type:
        lines.append(f"| **Type** | {finding.finding_type} |")
    if finding.auditor:
        lines.append(f"| **Auditor** | {finding.auditor} |")
    if finding.report_date:
        lines.append(f"| **Report Date** | {finding.report_date} |")
    if finding.source_report:
        lines.append(f"| **Source** | `{finding.source_report}` |")
    if finding.tags:
        lines.append(f"| **Tags** | {', '.join(f'`{t}`' for t in finding.tags)} |")
    lines.append("")

    # Description
    if finding.description:
        lines += [
            f"#### 📄 Description",
            f"",
            finding.description.strip(),
            f"",
        ]

    # Root Cause
    if finding.root_cause:
        lines += [
            f"#### 🔍 Root Cause",
            f"",
            finding.root_cause.strip(),
            f"",
        ]

    # Impact
    if finding.impact:
        lines += [
            f"#### 💥 Impact",
            f"",
            finding.impact.strip(),
            f"",
        ]

    # Likelihood
    if finding.likelihood:
        lines += [
            f"#### 📊 Likelihood / Difficulty",
            f"",
            finding.likelihood.strip(),
            f"",
        ]

    # Affected Locations
    locs = []
    if finding.affected_contracts:
        locs.append(f"**Contracts:** {', '.join(f'`{c}`' for c in finding.affected_contracts)}")
    if finding.affected_functions:
        locs.append(f"**Functions:** {', '.join(f'`{f}`' for f in finding.affected_functions)}")
    if finding.affected_lines:
        locs.append(f"**Lines:** {', '.join(f'`{l}`' for l in finding.affected_lines)}")
    if locs:
        lines += [
            f"#### 📍 Affected Locations",
            f"",
            *locs,
            f"",
        ]

    # Vulnerable Code
    if finding.vulnerable_code:
        lines += [
            f"#### ⚠️ Vulnerable Code",
            f"",
        ]
        for snippet in finding.vulnerable_code:
            if snippet.description:
                lines.append(f"*{snippet.description}*")
            if snippet.file_ref:
                lines.append(f"`{snippet.file_ref}`")
            lines += [
                f"```{snippet.language}",
                snippet.code.rstrip(),
                f"```",
                f"",
            ]

    # Proof of Concept
    if finding.proof_of_concept:
        lines += [
            f"#### 🧪 Proof of Concept",
            f"",
            finding.proof_of_concept.strip(),
            f"",
        ]

    if finding.attack_scenario and finding.attack_scenario != finding.proof_of_concept:
        lines += [
            f"#### ⚔️ Attack Scenario",
            f"",
            finding.attack_scenario.strip(),
            f"",
        ]

    # Recommendation
    if finding.recommendation:
        lines += [
            f"#### ✅ Recommendation",
            f"",
            finding.recommendation.strip(),
            f"",
        ]

    # Fixed Code
    if finding.fixed_code:
        lines += [
            f"#### 🔧 Fixed / Recommended Code",
            f"",
        ]
        for snippet in finding.fixed_code:
            if snippet.description:
                lines.append(f"*{snippet.description}*")
            lines += [
                f"```{snippet.language}",
                snippet.code.rstrip(),
                f"```",
                f"",
            ]

    # Fix Description
    if finding.fix_description:
        lines += [
            f"#### 📝 Fix Description",
            f"",
            finding.fix_description.strip(),
            f"",
        ]

    # AI Check Points
    if finding.check_points:
        lines += [
            f"#### 🎯 What to Verify in New Code",
            f"",
            *[f"- {cp}" for cp in finding.check_points],
            f"",
        ]

    # Raw section (optional)
    if include_raw and finding.raw_section:
        lines += [
            f"<details>",
            f"<summary>📜 Raw Extracted Text</summary>",
            f"",
            f"```",
            finding.raw_section[:3000],
            f"```",
            f"",
            f"</details>",
            f"",
        ]

    lines += ["---", ""]
    return lines


def generate_aggregated_markdown_report(
    db: AggregatedDatabase,
    output_path: Optional[Path] = None,
) -> str:
    """
    Generate a comprehensive aggregated Markdown report from multiple audit reports.
    Groups findings by severity, then by report.
    """
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines += [
        f"# 🗂 Aggregated Audit Findings Database",
        f"",
        f"> Generated by AuditTool on {now}",
        f"> {db.total_reports} reports | {len(db.all_findings)} total findings",
        f"",
        f"---",
        f"",
        f"## 📊 Overall Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Reports | **{db.total_reports}** |",
        f"| Total Findings | **{len(db.all_findings)}** |",
        f"",
        f"### By Severity",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]

    for sev, findings in db.by_severity.items():
        emoji = SEVERITY_EMOJI.get(sev, "❓")
        lines.append(f"| {emoji} **{sev.upper()}** | {len(findings)} |")

    lines += ["", "---", ""]

    # Per-report summaries
    lines += [
        f"## 📋 Reports Processed",
        f"",
        f"| # | File | Auditor | Project | Date | Findings |",
        f"|---|------|---------|---------|------|----------|",
    ]
    for i, report in enumerate(db.reports, 1):
        lines.append(
            f"| {i} | `{Path(report.source_file).name}` | "
            f"{report.auditor or '—'} | {report.project_name or '—'} | "
            f"{report.report_date or '—'} | {report.total_findings} |"
        )
    lines += ["", "---", ""]

    # Full findings by severity
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFORMATIONAL, Severity.GAS]:
        sev_findings = db.by_severity.get(sev.value, [])
        if not sev_findings:
            continue

        emoji = SEVERITY_EMOJI.get(sev.value, "❓")
        lines += [
            f"## {emoji} {sev.value.upper()} Findings ({len(sev_findings)})",
            f"",
        ]

        for i, finding in enumerate(sev_findings, 1):
            lines += _finding_to_markdown(finding, i, len(sev_findings))

    lines += [
        f"---",
        f"",
        f"*Report generated by AuditTool — Smart Contract Audit Extractor*",
        f"*{now}*",
    ]

    content = "\n".join(lines)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

    return content


def _make_anchor(text: str) -> str:
    """Convert text to a GitHub-style markdown anchor."""
    import re
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"\s+", "-", text.strip())
    return text[:80]
