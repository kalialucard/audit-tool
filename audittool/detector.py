"""
Report type detector — identifies the format and auditor style of an audit report.
Supports: PDF, Markdown, HTML, Text
Auditor styles: Code4rena, Sherlock, Trail of Bits, OpenZeppelin, Cantina/Spearbit,
                Sigma Prime, ChainSecurity, Halborn, Certora, ConsenSys Diligence,
                Cyfrin, Guardian, Peckshield, SlowMist, Generic
"""

from __future__ import annotations
import os
import re
from pathlib import Path
from audittool.models import ReportFormat


# ─── Auditor Style Fingerprints ───────────────────────────────────────────────
# Each entry: (style_name, [regex patterns that identify it])
AUDITOR_FINGERPRINTS: list[tuple[str, list[str]]] = [
    ("Code4rena", [
        r"\[\[H-\d+\]",
        r"\[\[M-\d+\]",
        r"code4rena",
        r"c4udit",
        r"Warden",
        r"\[H-\d+\].*\n.*\*\*Severity",
    ]),
    ("Sherlock", [
        r"sherlock",
        r"sherlockdefi",
        r"High Severity Issues",
        r"Medium Severity Issues",
        r"## \d+\. .+\n+.*\*\*Vulnerability Detail",
    ]),
    ("Trail of Bits", [
        r"Trail of Bits",
        r"TOB-[A-Z]+-\d+",
        r"trailofbits",
        r"\*\*Finding ID:\*\* TOB",
        r"Difficulty:\s*(Undetermined|Easy|Medium|Hard)",
    ]),
    ("OpenZeppelin", [
        r"OpenZeppelin",
        r"openzeppelin\.com",
        r"\d+\. .+\[(?:Critical|High|Medium|Low|Informational)\]",
        r"OZ-\d+",
    ]),
    ("Cantina", [
        r"cantina\.xyz",
        r"Cantina",
        r"\[C-\d+\]",
        r"\[H-\d+\].*\n.*\*\*Severity.*Critical",
    ]),
    ("Spearbit", [
        r"Spearbit",
        r"spearbit\.com",
        r"SPEAR-[A-Z]+-\d+",
    ]),
    ("Sigma Prime", [
        r"Sigma Prime",
        r"sigmaprime\.io",
        r"SCP-[A-Z]+-\d+",
    ]),
    ("ChainSecurity", [
        r"ChainSecurity",
        r"chainsecurity\.com",
        r"CS-[A-Z]+-\d+",
    ]),
    ("Halborn", [
        r"Halborn",
        r"halborn\.com",
        r"HAL-\d+",
    ]),
    ("Certora", [
        r"Certora",
        r"certora\.com",
    ]),
    ("ConsenSys Diligence", [
        r"ConsenSys",
        r"Diligence",
        r"diligence\.consensys",
        r"MED-\d+",
        r"CRI-\d+",
    ]),
    ("Cyfrin", [
        r"Cyfrin",
        r"cyfrin\.io",
        r"\[S-\d+\]",
    ]),
    ("Guardian Audits", [
        r"Guardian Audits",
        r"guardianaudits",
    ]),
    ("PeckShield", [
        r"PeckShield",
        r"peckshield\.com",
    ]),
    ("SlowMist", [
        r"SlowMist",
        r"slowmist\.com",
    ]),
    ("Aderyn", [
        r"aderyn",
        r"cyfrin/aderyn",
        r"\| Severity \| Title \| Instance Count",
    ]),
]


# ─── File Format Detection ────────────────────────────────────────────────────

def detect_format(path: Path) -> ReportFormat:
    """Detect the file format from extension and magic bytes."""
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return ReportFormat.PDF

    if suffix in (".md", ".markdown"):
        return ReportFormat.MARKDOWN

    if suffix in (".html", ".htm"):
        return ReportFormat.HTML

    if suffix == ".txt":
        return ReportFormat.TEXT

    # Peek at file content for magic detection
    try:
        with open(path, "rb") as f:
            header = f.read(8)
        if header[:4] == b"%PDF":
            return ReportFormat.PDF
        if header[:5] in (b"<html", b"<!DOC", b"<HTML"):
            return ReportFormat.HTML
    except Exception:
        pass

    # Try reading as text to detect markdown
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")[:2000]
        if re.search(r"^#{1,6}\s+.+", content, re.MULTILINE):
            return ReportFormat.MARKDOWN
        if re.search(r"<html|<!doctype", content, re.IGNORECASE):
            return ReportFormat.HTML
    except Exception:
        pass

    return ReportFormat.TEXT


# ─── Auditor Style Detection ──────────────────────────────────────────────────

def detect_auditor_style(text: str) -> str:
    """
    Detect the auditing firm/style from report text.
    Returns the auditor name or 'Generic'.
    """
    text_lower = text.lower()
    sample = text[:8000]  # Only check the beginning + end

    best_match: str = "Generic"
    best_score: int = 0

    for auditor_name, patterns in AUDITOR_FINGERPRINTS:
        score = 0
        for pattern in patterns:
            if re.search(pattern, sample, re.IGNORECASE | re.MULTILINE):
                score += 1
        if score > best_score:
            best_score = score
            best_match = auditor_name

    return best_match


def detect_project_name(text: str, filename: str) -> str:
    """
    Try to extract the project/protocol name from the report text or filename.
    """
    # Common patterns in report headers
    patterns = [
        r"(?:Security (?:Audit|Review)|Audit Report) (?:of|for|–|-)\s+([A-Za-z0-9 _\-\.]+?)(?:\n|v\d|\s{2,})",
        r"^#\s+([A-Za-z0-9 _\-\.]+?)(?:\s+Security|\s+Audit|\s+Smart Contract)",
        r"Project(?:\s+Name)?:\s*([A-Za-z0-9 _\-\.]+)",
        r"Protocol(?:\s+Name)?:\s*([A-Za-z0-9 _\-\.]+)",
        r"Client:\s*([A-Za-z0-9 _\-\.]+)",
        r"^#\s+([A-Za-z0-9 _\-\.]{3,40})\s*$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text[:3000], re.MULTILINE | re.IGNORECASE)
        if match:
            name = match.group(1).strip().rstrip(".")
            if 2 < len(name) < 60:
                return name

    # Fall back to filename
    stem = Path(filename).stem
    # Clean common suffixes
    stem = re.sub(r"[-_](audit|report|security|review|final|v\d+\.?\d*).*$", "", stem, flags=re.IGNORECASE)
    return stem.replace("-", " ").replace("_", " ").title() or "Unknown Project"


def detect_report_date(text: str) -> str:
    """Try to extract the report date."""
    patterns = [
        r"(?:Date|Published|Report Date|Audit Date):\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",
        r"(?:Date|Published|Report Date|Audit Date):\s*(\w+ \d{1,2},?\s*\d{4})",
        r"(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s*\d{4}",
        r"\d{4}-\d{2}-\d{2}",
        r"\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}",
    ]
    for pattern in patterns:
        match = re.search(pattern, text[:4000], re.IGNORECASE)
        if match:
            return match.group(0).strip()
    return ""


def detect_scope(text: str) -> tuple[list[str], list[str]]:
    """
    Try to extract in-scope and out-of-scope contracts from the report text.
    Returns (in_scope, out_of_scope).
    """
    in_scope: list[str] = []
    out_of_scope: list[str] = []

    # Look for scope sections
    scope_section = re.search(
        r"(?:Scope|In[- ]?Scope|Audit Scope|Files in Scope)\s*\n(.*?)(?=\n#{1,3}|\Z)",
        text[:6000], re.DOTALL | re.IGNORECASE
    )
    if scope_section:
        section_text = scope_section.group(1)
        # Extract .sol file references
        sol_files = re.findall(r"[\w/]+\.sol(?:#[\w]+)?", section_text)
        in_scope.extend(sol_files)

    # Out of scope
    oos_section = re.search(
        r"(?:Out[- ]?of[- ]?Scope|Not in Scope)\s*\n(.*?)(?=\n#{1,3}|\Z)",
        text[:6000], re.DOTALL | re.IGNORECASE
    )
    if oos_section:
        section_text = oos_section.group(1)
        sol_files = re.findall(r"[\w/]+\.sol(?:#[\w]+)?", section_text)
        out_of_scope.extend(sol_files)

    return in_scope, out_of_scope


def detect_report_version(text: str) -> str:
    """Try to detect the contract/commit version from the report."""
    patterns = [
        r"[Cc]ommit(?:\s+[Hh]ash)?:\s*([a-f0-9]{7,40})",
        r"[Vv]ersion(?:\s+[Aa]udited)?:\s*(v?\d+\.\d+[\.\d]*)",
        r"[Tt]ag:\s*(v?\d+\.\d+[\.\d]*)",
        r"[Cc]ommit[:\s]+([a-f0-9]{7,40})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text[:5000])
        if match:
            return match.group(1).strip()
    return ""
