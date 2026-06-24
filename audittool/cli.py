"""
CLI entry point for AuditTool.

Commands:
  extract   — Parse one or more audit reports → JSON + Markdown
  list      — List all findings from a previously extracted JSON
  show      — Show full details of a specific finding
  summary   — Print a quick summary table
"""

from __future__ import annotations
import json
import sys
from pathlib import Path
from typing import Optional

import click

from audittool.models import AuditReport, AggregatedDatabase, Severity
from audittool.extractor import (
    extract_report, extract_directory, save_json, SUPPORTED_EXTENSIONS
)
from audittool.reporter import (
    print_banner, print_report_summary, print_finding,
    print_aggregated_summary,
    generate_markdown_report, generate_aggregated_markdown_report,
)


# ─── CLI Group ────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="audittool")
def cli():
    """
    \b
    AuditTool — Smart Contract Audit Report Extractor
    Zero AI dependency. Supports PDF, Markdown, HTML, Text.

    \b
    Usage examples:
      audittool extract report.pdf
      audittool extract ./audit-reports/ --output ./output/
      audittool extract report.md --show-findings
      audittool list ./output/findings.json
      audittool show ./output/findings.json H-01
      audittool summary ./output/findings.json
    """
    pass


# ─── EXTRACT Command ──────────────────────────────────────────────────────────

@cli.command("extract")
@click.argument("source", type=click.Path(exists=True))
@click.option("--output", "-o", default="./audit_output",
              help="Output directory for JSON and Markdown reports [default: ./audit_output]")
@click.option("--format", "-f", "out_format",
              type=click.Choice(["both", "json", "markdown"], case_sensitive=False),
              default="both", help="Output format [default: both]")
@click.option("--show-findings", "-s", is_flag=True, default=False,
              help="Print all findings to terminal after extraction")
@click.option("--severity", "-sev",
              type=click.Choice(["critical", "high", "medium", "low", "info", "gas", "all"],
                                case_sensitive=False),
              default="all",
              help="Filter findings by minimum severity [default: all]")
@click.option("--recursive/--no-recursive", default=True,
              help="Recurse into subdirectories [default: recursive]")
@click.option("--include-raw", is_flag=True, default=False,
              help="Include raw extracted text in Markdown output (useful for debugging)")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Verbose parsing output")
def extract_cmd(
    source: str,
    output: str,
    out_format: str,
    show_findings: bool,
    severity: str,
    recursive: bool,
    include_raw: bool,
    verbose: bool,
):
    """
    Extract all findings from an audit report or directory of reports.

    \b
    SOURCE can be:
      - A single file  (PDF, Markdown, HTML, or Text)
      - A directory    (all supported files are processed)

    \b
    Examples:
      audittool extract report.pdf
      audittool extract ./audits/ -o ./output/ --show-findings
      audittool extract ./audits/ --severity high --show-findings
    """
    print_banner()

    source_path = Path(source)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    severity_filter = _parse_severity_filter(severity)

    # ── Single File ──────────────────────────────────────────────────────────
    if source_path.is_file():
        _extract_single_file(
            source_path, output_path, out_format,
            show_findings, severity_filter, include_raw, verbose
        )

    # ── Directory ────────────────────────────────────────────────────────────
    elif source_path.is_dir():
        _extract_directory(
            source_path, output_path, out_format,
            show_findings, severity_filter, recursive, include_raw, verbose
        )

    else:
        click.echo(f"[ERROR] Source not found: {source}", err=True)
        sys.exit(1)


def _extract_single_file(
    path: Path, output_path: Path, out_format: str,
    show_findings: bool, severity_filter: Optional[set],
    include_raw: bool, verbose: bool
) -> None:
    """Handle single file extraction."""
    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        click.echo(f"[WARN] Unsupported file type: {ext}. Supported: {', '.join(SUPPORTED_EXTENSIONS)}")

    click.echo(f"\n🔍 Extracting: {path.name}")
    report = extract_report(path, verbose=verbose)

    # Apply severity filter
    if severity_filter:
        report.findings = [f for f in report.findings if f.severity in severity_filter]

    print_report_summary(report)

    if show_findings:
        _print_all_findings(report.findings)

    # Save outputs
    stem = path.stem
    if out_format in ("both", "json"):
        json_out = output_path / f"{stem}.json"
        save_json(report.to_dict(), json_out)
        click.echo(f"\n✅ JSON saved: {json_out}")

    if out_format in ("both", "markdown"):
        md_out = output_path / f"{stem}_report.md"
        generate_markdown_report(report, md_out, include_raw=include_raw)
        click.echo(f"✅ Markdown saved: {md_out}")

    click.echo(f"\n📊 Done. {report.total_findings} findings extracted.")


def _extract_directory(
    source_path: Path, output_path: Path, out_format: str,
    show_findings: bool, severity_filter: Optional[set],
    recursive: bool, include_raw: bool, verbose: bool
) -> None:
    """Handle directory extraction."""
    click.echo(f"\n🔍 Scanning directory: {source_path}")

    db = extract_directory(source_path, recursive=recursive, verbose=verbose)

    if not db.reports:
        click.echo("[WARN] No parseable audit reports found.")
        return

    # Apply severity filter across all findings
    if severity_filter:
        db.all_findings = [f for f in db.all_findings if f.severity in severity_filter]
        for report in db.reports:
            report.findings = [f for f in report.findings if f.severity in severity_filter]

    print_aggregated_summary(db)

    # Per-report terminal output
    for report in db.reports:
        print_report_summary(report)
        if show_findings:
            _print_all_findings(report.findings)

    # Save outputs
    if out_format in ("both", "json"):
        # Aggregated JSON
        agg_json = output_path / "all_findings.json"
        save_json(db.to_dict(), agg_json)
        click.echo(f"\n✅ Aggregated JSON: {agg_json}")

        # Per-report JSON
        for report in db.reports:
            stem = Path(report.source_file).stem
            json_out = output_path / f"{stem}.json"
            save_json(report.to_dict(), json_out)

    if out_format in ("both", "markdown"):
        # Aggregated Markdown
        agg_md = output_path / "all_findings_report.md"
        generate_aggregated_markdown_report(db, agg_md)
        click.echo(f"✅ Aggregated Markdown: {agg_md}")

        # Per-report Markdown
        for report in db.reports:
            stem = Path(report.source_file).stem
            md_out = output_path / f"{stem}_report.md"
            generate_markdown_report(report, md_out, include_raw=include_raw)

    click.echo(f"\n📊 Done. {db.total_reports} reports | {len(db.all_findings)} findings → {output_path}")


def _print_all_findings(findings) -> None:
    """Print all findings to terminal."""
    if not findings:
        click.echo("\n  (No findings to display)")
        return
    total = len(findings)
    for i, finding in enumerate(findings, 1):
        print_finding(finding, i, total)


def _parse_severity_filter(severity: str) -> Optional[set]:
    """Convert CLI severity arg to a set of Severity enums."""
    if severity == "all":
        return None
    sev_map = {
        "critical": {Severity.CRITICAL},
        "high": {Severity.CRITICAL, Severity.HIGH},
        "medium": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM},
        "low": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW},
        "info": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFORMATIONAL},
        "gas": {Severity.GAS},
    }
    return sev_map.get(severity.lower())


# ─── LIST Command ─────────────────────────────────────────────────────────────

@cli.command("list")
@click.argument("json_file", type=click.Path(exists=True))
@click.option("--severity", "-s",
              type=click.Choice(["critical", "high", "medium", "low", "info", "gas", "all"],
                                case_sensitive=False),
              default="all", help="Filter by severity")
@click.option("--status", "-st", default="all",
              help="Filter by status (fixed, acknowledged, etc.)")
@click.option("--tag", "-t", default="", help="Filter by vulnerability tag")
def list_cmd(json_file: str, severity: str, status: str, tag: str):
    """
    List all findings from a previously extracted JSON file.

    \b
    Examples:
      audittool list ./output/all_findings.json
      audittool list ./output/all_findings.json --severity high
      audittool list ./output/all_findings.json --tag reentrancy
      audittool list ./output/all_findings.json --status fixed
    """
    from audittool.extractor import load_json

    data = load_json(Path(json_file))
    findings_data = data.get("all_findings") or data.get("findings") or []

    severity_filter = _parse_severity_filter(severity)
    filtered = []

    for fd in findings_data:
        sev = Severity(fd.get("severity", "unknown"))
        if severity_filter and sev not in severity_filter:
            continue
        if status != "all" and fd.get("status", "").lower() != status.lower():
            continue
        if tag and tag.lower() not in [t.lower() for t in fd.get("tags", [])]:
            continue
        filtered.append(fd)

    if not filtered:
        click.echo("No findings match your filters.")
        return

    click.echo(f"\n{'#':<4} {'ID':<12} {'SEV':<14} {'STATUS':<18} {'TITLE'}")
    click.echo("─" * 90)

    sev_colors = {
        "critical": "\033[91m", "high": "\033[38;5;208m",
        "medium": "\033[93m", "low": "\033[96m",
        "informational": "\033[90m", "gas": "\033[92m",
    }

    for i, fd in enumerate(filtered, 1):
        sev = fd.get("severity", "unknown")
        color = sev_colors.get(sev, "")
        reset = "\033[0m"
        title = (fd.get("title") or "")[:55]
        fid = (fd.get("finding_id") or "")[:11]
        stat = (fd.get("status") or "unknown")[:16]
        emoji = SEVERITY_EMOJI_plain.get(sev, "?")
        click.echo(f"{i:<4} {fid:<12} {color}{emoji} {sev:<11}{reset} {stat:<18} {title}")

    click.echo(f"\n{len(filtered)} findings shown")


SEVERITY_EMOJI_plain = {
    "critical": "🔴", "high": "🟠", "medium": "🟡",
    "low": "🔵", "informational": "⚪", "gas": "⛽", "unknown": "❓",
}


# ─── SHOW Command ─────────────────────────────────────────────────────────────

@cli.command("show")
@click.argument("json_file", type=click.Path(exists=True))
@click.argument("finding_id")
def show_cmd(json_file: str, finding_id: str):
    """
    Show full details of a specific finding by ID.

    \b
    Examples:
      audittool show ./output/all_findings.json H-01
      audittool show ./output/all_findings.json TOB-XX-3
      audittool show ./output/all_findings.json F-042
    """
    from audittool.extractor import load_json
    from audittool.models import Finding, Severity, Status, CodeSnippet
    from dataclasses import fields as dc_fields

    data = load_json(Path(json_file))
    findings_data = data.get("all_findings") or data.get("findings") or []

    # Find matching finding
    match = None
    for fd in findings_data:
        fid = (fd.get("finding_id") or "").strip()
        if fid.lower() == finding_id.lower():
            match = fd
            break
        # Also try title search
        if finding_id.lower() in (fd.get("title") or "").lower():
            match = fd
            break

    if not match:
        click.echo(f"[ERROR] Finding '{finding_id}' not found.")
        click.echo("Use 'audittool list' to see available finding IDs.")
        sys.exit(1)

    # Reconstruct Finding object
    f = Finding()
    f.finding_id = match.get("finding_id", "")
    f.title = match.get("title", "")
    f.severity = Severity(match.get("severity", "unknown"))
    f.status = Status(match.get("status", "unknown"))
    f.description = match.get("description", "")
    f.root_cause = match.get("root_cause", "")
    f.impact = match.get("impact", "")
    f.likelihood = match.get("likelihood", "")
    f.proof_of_concept = match.get("proof_of_concept", "")
    f.attack_scenario = match.get("attack_scenario", "")
    f.recommendation = match.get("recommendation", "")
    f.fix_description = match.get("fix_description", "")
    f.affected_contracts = match.get("affected_contracts", [])
    f.affected_functions = match.get("affected_functions", [])
    f.affected_lines = match.get("affected_lines", [])
    f.tags = match.get("tags", [])
    f.check_points = match.get("check_points", [])
    f.finding_type = match.get("finding_type", "")
    f.source_report = match.get("source_report", "")
    f.auditor = match.get("auditor", "")
    f.report_date = match.get("report_date", "")
    for vc in match.get("vulnerable_code", []):
        f.vulnerable_code.append(CodeSnippet(**vc))
    for fc in match.get("fixed_code", []):
        f.fixed_code.append(CodeSnippet(**fc))

    print_finding(f, 1, 1)


# ─── SUMMARY Command ──────────────────────────────────────────────────────────

@cli.command("summary")
@click.argument("json_file", type=click.Path(exists=True))
def summary_cmd(json_file: str):
    """
    Print a quick summary of extracted findings.

    \b
    Example:
      audittool summary ./output/all_findings.json
    """
    from audittool.extractor import load_json

    data = load_json(Path(json_file))
    print_banner()

    # Aggregated or single report?
    if "reports" in data:
        click.echo(f"\n📁 Reports: {data['summary']['total_reports']}")
        click.echo(f"📊 Total Findings: {data['summary']['total_findings']}")
        click.echo(f"\nBy Severity:")
        for sev, count in (data.get("summary", {}).get("by_severity") or {}).items():
            emoji = SEVERITY_EMOJI_plain.get(sev, "?")
            click.echo(f"  {emoji} {sev.upper():<18} {count}")
    else:
        summary = data.get("summary", {})
        click.echo(f"\n📁 Report: {data.get('source_file', 'Unknown')}")
        click.echo(f"🏢 Auditor: {data.get('auditor', 'Unknown')}")
        click.echo(f"📅 Date: {data.get('report_date', 'Unknown')}")
        click.echo(f"📊 Total Findings: {summary.get('total_findings', 0)}")
        click.echo(f"\nBy Severity:")
        for sev, count in (summary.get("by_severity") or {}).items():
            emoji = SEVERITY_EMOJI_plain.get(sev, "?")
            click.echo(f"  {emoji} {sev.upper():<18} {count}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    cli()


if __name__ == "__main__":
    main()
