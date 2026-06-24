"""
Main extractor — orchestrates parsing of all report files.
Handles format detection, parsing, and enrichment.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

from audittool.models import (
    AuditReport, AggregatedDatabase, Finding, ReportFormat
)
from audittool.detector import (
    detect_format, detect_auditor_style, detect_project_name,
    detect_report_date, detect_scope, detect_report_version
)


SUPPORTED_EXTENSIONS = {".pdf", ".md", ".markdown", ".html", ".htm", ".txt"}


def extract_report(path: Path, verbose: bool = False) -> AuditReport:
    """
    Extract all findings from a single audit report file.
    Auto-detects format and auditor style.
    """
    report = AuditReport()
    report.source_file = str(path)

    # ── Format Detection ────────────────────────────────────────────────────
    fmt = detect_format(path)
    report.report_format = fmt

    # ── Parse to Raw Text ───────────────────────────────────────────────────
    raw_text = _get_raw_text(path, fmt, verbose)
    if not raw_text:
        if verbose:
            print(f"  [WARN] Could not extract text from {path.name}")
        return report

    # ── Metadata Extraction ─────────────────────────────────────────────────
    report.auditor = detect_auditor_style(raw_text)
    report.project_name = detect_project_name(raw_text, path.name)
    report.report_date = detect_report_date(raw_text)
    report.report_version = detect_report_version(raw_text)
    scope, oos = detect_scope(raw_text)
    report.scope = scope
    report.out_of_scope = oos

    # ── Finding Extraction ──────────────────────────────────────────────────
    findings = _extract_findings(path, fmt, raw_text, verbose)

    # Enrich each finding with report metadata
    for finding in findings:
        finding.source_report = path.name
        finding.auditor = report.auditor
        finding.report_date = report.report_date
        finding.report_version = report.report_version
        # Auto-number if no ID was found
        if not finding.finding_id:
            finding.finding_id = f"F-{findings.index(finding)+1:03d}"

    report.findings = findings
    return report


def _get_raw_text(path: Path, fmt: ReportFormat, verbose: bool) -> str:
    """Convert a file to raw text based on its format."""
    try:
        if fmt == ReportFormat.PDF:
            from audittool.parsers.pdf_parser import parse_pdf
            return parse_pdf(path)

        elif fmt == ReportFormat.HTML:
            from audittool.parsers.html_parser import parse_html
            return parse_html(path)

        else:  # Markdown or Text
            return path.read_text(encoding="utf-8", errors="ignore")

    except ImportError as e:
        if verbose:
            print(f"  [WARN] Missing dependency for {fmt.value}: {e}")
        # Try reading as plain text as fallback
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""
    except Exception as e:
        if verbose:
            print(f"  [ERROR] Failed to parse {path.name}: {e}")
        return ""


def _extract_findings(
    path: Path, fmt: ReportFormat, raw_text: str, verbose: bool
) -> list[Finding]:
    """Extract findings from raw text."""
    from audittool.parsers.markdown_parser import parse_markdown

    # All formats go through the markdown parser after text extraction
    _, findings = parse_markdown(path, raw_text)
    return findings


def extract_directory(
    source_dir: Path,
    recursive: bool = True,
    verbose: bool = False,
    file_filter: Optional[list[str]] = None,
) -> AggregatedDatabase:
    """
    Extract findings from all audit reports in a directory.
    Returns aggregated database.
    """
    db = AggregatedDatabase()

    # Collect all report files
    report_files: list[Path] = []
    if recursive:
        for ext in SUPPORTED_EXTENSIONS:
            report_files.extend(source_dir.rglob(f"*{ext}"))
    else:
        for ext in SUPPORTED_EXTENSIONS:
            report_files.extend(source_dir.glob(f"*{ext}"))

    # Apply name filter if given
    if file_filter:
        report_files = [
            f for f in report_files
            if any(pat.lower() in f.name.lower() for pat in file_filter)
        ]

    # Sort for deterministic order
    report_files.sort()

    if not report_files:
        if verbose:
            print(f"[WARN] No report files found in {source_dir}")
        return db

    total = len(report_files)
    for i, path in enumerate(report_files, 1):
        if verbose:
            print(f"  [{i}/{total}] Parsing {path.name}...")
        try:
            report = extract_report(path, verbose=verbose)
            if report.findings or verbose:
                db.reports.append(report)
                db.all_findings.extend(report.findings)
                if verbose:
                    print(f"    → {len(report.findings)} findings "
                          f"({report.auditor}, {report.project_name})")
        except Exception as e:
            if verbose:
                print(f"  [ERROR] {path.name}: {e}")

    return db


def save_json(data: dict, output_path: Path) -> None:
    """Save data as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def load_json(input_path: Path) -> dict:
    """Load JSON data."""
    with open(input_path, "r", encoding="utf-8") as f:
        return json.load(f)
