"""
Markdown/Text parser + Finding extractor.

Supports all major audit firm formats:
  - Code4rena   : ## [H-01] Title / [[H-01]] Title
  - Sherlock     : ## N. Title \n **Vulnerability Detail**
  - Trail of Bits: ## Finding N: Title + **Finding ID:** TOB-XX-N
  - OpenZeppelin : ### N. Title [High] / N. Title\n**Severity:** High
  - Cantina/Spearbit: ### [C-01] Title
  - Sigma Prime  : ### SCP-XX-N: Title
  - Cyfrin       : ### [S-01] Title (Aderyn-style too)
  - Halborn      : ### HAL-01 Title
  - Generic      : any heading containing severity keywords

Each extracted Finding is populated with ALL available fields:
  title, severity, status, description, root_cause, impact,
  vulnerable_code, proof_of_concept, recommendation, fixed_code,
  affected_contracts, affected_functions, affected_lines, check_points
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Optional

from audittool.models import (
    Finding, CodeSnippet, Severity, Status
)

# ─── Severity Normalization ────────────────────────────────────────────────────

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit":     Severity.CRITICAL,
    "c":        Severity.CRITICAL,
    "high":     Severity.HIGH,
    "h":        Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "med":      Severity.MEDIUM,
    "m":        Severity.MEDIUM,
    "low":      Severity.LOW,
    "l":        Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info":     Severity.INFORMATIONAL,
    "i":        Severity.INFORMATIONAL,
    "note":     Severity.INFORMATIONAL,
    "gas":      Severity.GAS,
    "optimization": Severity.GAS,
    "undetermined": Severity.UNKNOWN,
}

STATUS_MAP: dict[str, Status] = {
    "fixed":            Status.FIXED,
    "resolved":         Status.FIXED,
    "remediated":       Status.FIXED,
    "mitigated":        Status.MITIGATED,
    "acknowledged":     Status.ACKNOWLEDGED,
    "accepted":         Status.ACKNOWLEDGED,
    "won't fix":        Status.WONT_FIX,
    "wont fix":         Status.WONT_FIX,
    "will not fix":     Status.WONT_FIX,
    "partially fixed":  Status.PARTIALLY_FIXED,
    "partially resolved": Status.PARTIALLY_FIXED,
    "disputed":         Status.DISPUTED,
    "invalid":          Status.DISPUTED,
}

# ─── Vulnerability Tag Auto-Detection ─────────────────────────────────────────

VULN_TAG_PATTERNS: list[tuple[str, str]] = [
    ("reentrancy",      r"reentr(?:ancy|ant)"),
    ("access-control",  r"access[- ]control|unauthorized|privilege|permiss|onlyOwner|onlyRole|modifier"),
    ("integer-overflow", r"overflow|underflow|SafeMath|unchecked arith"),
    ("integer-underflow", r"underflow"),
    ("front-running",   r"front.?run|sandwich|MEV|miner"),
    ("flash-loan",      r"flash.?loan"),
    ("price-manipulation", r"price.?manipul|oracle.?manipul"),
    ("oracle-manipulation", r"oracle"),
    ("dos",             r"\bDoS\b|denial.?of.?service|gas.?limit|block.?gas"),
    ("unchecked-return", r"unchecked.?return|return.?value|transfer.*without|\.transfer\("),
    ("delegate-call",   r"delegatecall|delegate.?call"),
    ("selfdestruct",    r"selfdestruct|suicide\("),
    ("tx-origin",       r"tx\.origin"),
    ("signature-replay", r"signature.?replay|replay.?attack|nonce"),
    ("storage-collision", r"storage.?collision|proxy.?storage"),
    ("initialization",  r"initializ|constructor|__init"),
    ("logic-error",     r"logic.?error|incorrect.?calculation|wrong.?assumption"),
    ("rounding",        r"round(?:ing|ed|s)|precision|truncat"),
    ("timestamp",       r"timestamp|block\.timestamp|time.?manipul"),
    ("centralization",  r"centraliz|single.?point|admin.?key|owner.?control"),
    ("token-approval",  r"approve|allowance|transferFrom"),
    ("erc20",           r"ERC.?20|token.?transfer|safeTransfer"),
    ("erc721",          r"ERC.?721|NFT|tokenId"),
    ("governance",      r"governance|voting|proposal"),
    ("upgradeable",     r"upgrad(?:eable|able)|proxy|implementation"),
    ("cross-contract",  r"cross.?contract|external.?call|call\{value"),
    ("race-condition",  r"race.?condition|TOCTOU|check.?effect"),
    ("missing-validation", r"missing.?check|lack.?of.?valid|no.?validat|without.?check"),
    ("hardcoded",       r"hardcod|magic.?number|magic.?value"),
    ("infinite-loop",   r"infinite.?loop|unbounded.?loop|gas.?exhaustion"),
]


def normalize_severity(text: str) -> Severity:
    """Normalize a severity string to a Severity enum value."""
    clean = text.strip().lower().rstrip(":")
    return SEVERITY_MAP.get(clean, Severity.UNKNOWN)


def normalize_status(text: str) -> Status:
    """Normalize a status string to a Status enum value."""
    clean = text.strip().lower()
    for key, value in STATUS_MAP.items():
        if key in clean:
            return value
    return Status.UNKNOWN


def detect_tags(text: str) -> list[str]:
    """Auto-detect vulnerability tags from finding text."""
    tags: list[str] = []
    text_lower = text.lower()
    for tag, pattern in VULN_TAG_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            tags.append(tag)
    return tags


def extract_code_blocks(text: str) -> list[CodeSnippet]:
    """
    Extract all fenced code blocks from markdown text.
    Returns list of CodeSnippet objects.
    """
    snippets: list[CodeSnippet] = []
    # Match ```lang ... ``` blocks
    pattern = re.compile(
        r"```(\w*)\n(.*?)```",
        re.DOTALL
    )
    for match in pattern.finditer(text):
        lang = match.group(1).strip() or "solidity"
        code = match.group(2).rstrip()
        if code.strip():
            snippets.append(CodeSnippet(code=code, language=lang))

    # Also match indented code blocks (4 spaces)
    indent_pattern = re.compile(r"(?:^|\n)((?:    .+\n?)+)", re.MULTILINE)
    for match in indent_pattern.finditer(text):
        code = re.sub(r"^    ", "", match.group(1), flags=re.MULTILINE).strip()
        if code and len(code) > 20:
            snippets.append(CodeSnippet(code=code, language="solidity"))

    return snippets


def extract_file_refs(text: str) -> tuple[list[str], list[str], list[str]]:
    """
    Extract affected contracts, functions, and line references.
    Returns (contracts, functions, line_refs).
    """
    contracts: list[str] = []
    functions: list[str] = []
    line_refs: list[str] = []

    # .sol file references  e.g. Bridge.sol, contracts/Bridge.sol#L42
    for m in re.finditer(r"[\w/\-.]+\.sol(?:#L?\d+(?:-L?\d+)?)?", text):
        ref = m.group(0)
        if "#" in ref or "L" in ref.split(".sol")[-1]:
            line_refs.append(ref)
        contracts.append(ref.split("#")[0])

    # Function references  e.g. withdrawFunds(), _transfer(address,uint256)
    for m in re.finditer(r"\b([a-z_][a-zA-Z0-9_]*)\s*\(([^)]{0,60})\)", text):
        fname = m.group(1)
        # Filter out common non-function words
        skip = {"if", "for", "while", "require", "emit", "return", "revert",
                 "assert", "modifier", "event", "struct", "mapping", "address",
                 "uint", "int", "bool", "bytes", "string"}
        if fname not in skip and len(fname) > 2:
            functions.append(f"{fname}()")

    # Deduplicate preserving order
    contracts = list(dict.fromkeys(contracts))
    functions = list(dict.fromkeys(functions))
    line_refs = list(dict.fromkeys(line_refs))

    return contracts[:20], functions[:20], line_refs[:30]


def generate_check_points(finding: Finding) -> list[str]:
    """
    Generate AI checklist from finding's tags, description and root cause.
    These help an AI auditor know what to verify in new code.
    """
    checks: list[str] = []
    combined = (finding.description + " " + finding.root_cause + " " + finding.title).lower()

    # Tag-based check generation
    if "reentrancy" in finding.tags:
        checks.append("Check all external calls — ensure state updates happen BEFORE external calls (CEI pattern)")
        checks.append("Look for call{value:...}() or .transfer() followed by state writes")

    if "access-control" in finding.tags:
        checks.append("Verify all sensitive functions have proper access modifiers (onlyOwner, onlyRole, etc.)")
        checks.append("Check that privilege-changing functions are protected")

    if "integer-overflow" in finding.tags:
        checks.append("Inspect all arithmetic operations for potential overflow/underflow")
        checks.append("Confirm unchecked{} blocks are intentional and safe")

    if "oracle-manipulation" in finding.tags:
        checks.append("Check if price/oracle data can be manipulated (flash loan, low liquidity)")
        checks.append("Verify TWAP or multi-source oracles are used for critical price reads")

    if "flash-loan" in finding.tags:
        checks.append("Check if flash-loan-powered attacks can exploit state changes within single tx")

    if "front-running" in finding.tags:
        checks.append("Look for operations sensitive to transaction ordering or mempool visibility")

    if "unchecked-return" in finding.tags:
        checks.append("Ensure return values from external calls (.transfer, .call, ERC20.transfer) are checked")

    if "signature-replay" in finding.tags:
        checks.append("Check that all signed messages include nonce, chainId, and contract address")
        checks.append("Verify signatures cannot be replayed across chains or function calls")

    if "initialization" in finding.tags:
        checks.append("Confirm initializer functions can only be called once")
        checks.append("Check for uninitialized storage or missing __init calls")

    if "logic-error" in finding.tags:
        checks.append("Carefully review calculation logic against the spec/documentation")

    if "missing-validation" in finding.tags:
        checks.append("Check that all user inputs and external call results are validated")
        checks.append("Look for missing zero-address, zero-amount, or bounds checks")

    if "centralization" in finding.tags:
        checks.append("Identify single points of failure — privileged roles that can break the protocol")

    if "delegate-call" in finding.tags:
        checks.append("Review all delegatecall targets — ensure storage layouts match")

    if "timestamp" in finding.tags:
        checks.append("Check if block.timestamp reliance can be exploited by miners")

    # Generic check from severity
    if finding.severity == Severity.CRITICAL:
        checks.append(f"PRIORITY CHECK: This is a critical pattern — '{finding.title[:60]}' — verify it cannot occur in the new code")
    elif finding.severity == Severity.HIGH:
        checks.append(f"HIGH PRIORITY: Verify the pattern from '{finding.title[:60]}' is not present")

    # Dedup
    seen: set[str] = set()
    unique_checks: list[str] = []
    for c in checks:
        key = c[:40].lower()
        if key not in seen:
            seen.add(key)
            unique_checks.append(c)

    return unique_checks or ["Review this function/contract carefully for the described pattern"]


# ─── Finding Section Splitters ─────────────────────────────────────────────────

# Patterns that identify the START of a new finding section
FINDING_HEADER_PATTERNS: list[tuple[str, str]] = [
    # Code4rena: ## [H-01] Title or ## [[H-01]] Title
    ("code4rena",  r"^#{1,4}\s+\[{1,2}([CHML]-\d+|[CHMLIGchmliq]-\d+|[Hh]igh-\d+|[Mm]ed-\d+)\].*"),
    # Sherlock: ## 1. Title (numbered findings)
    ("sherlock",   r"^#{2,3}\s+\d+\.\s+.+"),
    # Trail of Bits: ## Finding N: Title
    ("tob",        r"^#{1,3}\s+Finding\s+\d+[:\s].+"),
    # TOB ID style: ### TOB-XX-N: Title
    ("tob_id",     r"^#{1,4}\s+TOB-[A-Z]+-\d+[:\s].+"),
    # OpenZeppelin: ### N. Title [Severity]
    ("oz",         r"^#{2,4}\s+\d+\.\s+.+\[(?:Critical|High|Medium|Low|Info)\]"),
    # Cantina/Spearbit: ### [C-01] Title or ### [H-01] Title
    ("cantina",    r"^#{2,4}\s+\[[CHMLIG]-\d+\]\s*.+"),
    # Sigma Prime: #### SCP-XX-N: Title
    ("sigma",      r"^#{2,5}\s+SCP-[A-Z]+-\d+[:\s].+"),
    # Halborn: ### HAL-01 Title
    ("halborn",    r"^#{2,4}\s+HAL-\d+\s*.+"),
    # Cyfrin: ### [H-01]: Title
    ("cyfrin",     r"^#{2,4}\s+\[[CHMLIG]-\d+\]\s*:?\s*.+"),
    # Generic severity heading: ### High: Title or ## [High] Title
    ("generic_sev",r"^#{1,4}\s+(?:Critical|High|Medium|Low|Informational|Info)(?:\s*[:–\-]\s*|\s+).{3,}"),
    # Generic numbered: ## Finding 1 or ## Issue 1:
    ("generic_num",r"^#{1,4}\s+(?:Finding|Issue|Vulnerability|Bug|Problem)\s+\d+[:\s].+"),
    # Fallback: any heading with severity keywords in it
    ("fallback",   r"^#{2,4}\s+.{5,100}$"),
]


def split_into_finding_sections(text: str) -> list[str]:
    """
    Split report text into individual finding sections.
    Returns list of raw finding text blocks.
    """
    lines = text.split("\n")

    # Try each pattern style to find finding headers
    header_line_indices: list[int] = []

    # First pass: find all lines that look like finding headers
    for i, line in enumerate(lines):
        line = line.rstrip()
        for style, pattern in FINDING_HEADER_PATTERNS:
            if re.match(pattern, line, re.IGNORECASE):
                # Additional filter: must contain severity or ID-like content
                if _is_likely_finding_header(line):
                    header_line_indices.append(i)
                    break

    # Deduplicate adjacent matches
    header_line_indices = _deduplicate_headers(header_line_indices, lines)

    if not header_line_indices:
        # Last resort: look for severity keyword sections
        header_line_indices = _fallback_severity_split(lines)

    if not header_line_indices:
        # Return entire text as one finding
        return [text]

    # Split text at header positions
    sections: list[str] = []
    for idx, start in enumerate(header_line_indices):
        end = header_line_indices[idx + 1] if idx + 1 < len(header_line_indices) else len(lines)
        section = "\n".join(lines[start:end]).strip()
        if section and len(section) > 50:  # Skip trivially short sections
            sections.append(section)

    return sections


def _is_likely_finding_header(line: str) -> bool:
    """Check if a heading line is likely a finding (not a generic section heading)."""
    severity_keywords = {
        "critical", "high", "medium", "low", "informational", "info", "gas",
        "h-", "m-", "c-", "l-", "i-", "g-",
        "tob-", "hal-", "scp-", "spear-",
        "finding", "issue", "vulnerability", "bug",
    }
    line_lower = line.lower()

    # Skip common non-finding sections
    skip_sections = {
        "executive summary", "table of contents", "scope", "introduction",
        "conclusion", "appendix", "recommendations", "about", "disclaimer",
        "methodology", "overview", "background", "acknowledgements",
        "timeline", "severity classification", "severity levels",
        "out of scope", "in scope", "revision history",
    }
    for skip in skip_sections:
        if skip in line_lower:
            return False

    for kw in severity_keywords:
        if kw in line_lower:
            return True

    # Bracket pattern like [H-01] or [C-02]
    if re.search(r"\[[CHMLIG]-\d+\]", line, re.IGNORECASE):
        return True

    return False


def _deduplicate_headers(indices: list[int], lines: list[str]) -> list[int]:
    """Remove duplicate or too-close header indices."""
    if not indices:
        return []
    result = [indices[0]]
    for idx in indices[1:]:
        if idx - result[-1] >= 3:  # at least 3 lines apart
            result.append(idx)
    return result


def _fallback_severity_split(lines: list[str]) -> list[int]:
    """
    Last resort: split on severity section headers like:
    '## Critical Issues', '## High Severity', etc.
    """
    headers: list[int] = []
    for i, line in enumerate(lines):
        if re.match(
            r"^#{1,3}\s+(?:Critical|High|Medium|Low|Informational)\s*(?:Issues?|Findings?|Severity)?",
            line.strip(), re.IGNORECASE
        ):
            headers.append(i)
    return headers


# ─── Field Extraction from a Single Finding Section ──────────────────────────

def _extract_field(
    text: str,
    *label_patterns: str,
    multiline: bool = True,
    stop_labels: Optional[list[str]] = None,
) -> str:
    """
    Extract content after a labeled field header.
    Supports both inline ( **Label:** content ) and block formats.
    """
    stop_labels = stop_labels or []
    stop_pattern = ""
    if stop_labels:
        stops = "|".join(re.escape(s) for s in stop_labels)
        stop_pattern = rf"(?=\*{{1,2}}(?:{stops})\*{{1,2}}:|\n#{1,6}\s)"

    for label in label_patterns:
        escaped = re.escape(label)
        # Try: **Label:** value (bold markdown)
        pattern = rf"\*{{1,2}}{escaped}\*{{1,2}}:?\s*(.*?)\s*(?={stop_pattern}|\*{{1,2}}\w|\Z)" if not multiline else \
                  rf"\*{{1,2}}{escaped}\*{{1,2}}:?\s*(.*?)(?={stop_pattern}|\*{{1,2}}\w|\Z)"
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()

        # Try: Label: value (plain)
        pattern2 = rf"^{escaped}\s*:?\s*(.*?)(?={stop_pattern}|\n\n|\n#{1,6}\s|\Z)" if multiline else \
                   rf"^{escaped}\s*:?\s*(.+?)$"
        m = re.search(pattern2, text, re.DOTALL | re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip()

    return ""


def _extract_id_from_header(header_line: str) -> str:
    """Extract finding ID from the heading line."""
    # [H-01], [C-02], [[M-03]], TOB-XX-N, HAL-01, SCP-XX-N etc.
    patterns = [
        r"\[{1,2}([CHMLIG]-\d+)\]{1,2}",
        r"\b(TOB-[A-Z]+-\d+)\b",
        r"\b(HAL-\d+)\b",
        r"\b(SCP-[A-Z]+-\d+)\b",
        r"\b(SPEAR-[A-Z]+-\d+)\b",
        r"(?:Finding|Issue)\s+(\d+)",
        r"^#{1,4}\s+(\d+)\.\s",
    ]
    for pattern in patterns:
        m = re.search(pattern, header_line, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _extract_severity_from_text(text: str, header: str = "") -> Severity:
    """Extract severity from various formats in a finding section."""
    # Priority: explicit label first
    label_patterns = [
        r"\*{1,2}Severity\*{1,2}:?\s*(\w+)",
        r"Severity:?\s*(\w+)",
        r"\*{1,2}Risk\*{1,2}:?\s*(\w+)",
        r"Risk Level:?\s*(\w+)",
        r"Impact:?\s*(Critical|High|Medium|Low|Informational|Info|Gas)",
        r"Priority:?\s*(Critical|High|Medium|Low)",
    ]
    for p in label_patterns:
        m = re.search(p, text[:1000], re.IGNORECASE)
        if m:
            sev = normalize_severity(m.group(1))
            if sev != Severity.UNKNOWN:
                return sev

    # From header: [H-01] → High, [C-02] → Critical
    id_match = re.search(r"\[([CHMLIGI])-\d+\]", header, re.IGNORECASE)
    if id_match:
        letter = id_match.group(1).upper()
        letter_map = {"C": Severity.CRITICAL, "H": Severity.HIGH,
                      "M": Severity.MEDIUM, "L": Severity.LOW,
                      "I": Severity.INFORMATIONAL, "G": Severity.GAS}
        return letter_map.get(letter, Severity.UNKNOWN)

    # From header text: "[High]" or "High:" or "High Severity"
    for sev_str, sev_enum in [
        ("critical", Severity.CRITICAL), ("high", Severity.HIGH),
        ("medium", Severity.MEDIUM), ("low", Severity.LOW),
        ("informational", Severity.INFORMATIONAL), ("info", Severity.INFORMATIONAL),
        ("gas", Severity.GAS),
    ]:
        if re.search(rf"\b{sev_str}\b", header, re.IGNORECASE):
            return sev_enum

    return Severity.UNKNOWN


def _extract_status(text: str) -> Status:
    """Extract remediation status from a finding section."""
    patterns = [
        r"\*{1,2}Status\*{1,2}:?\s*([^\n\*]+)",
        r"Status:?\s*([^\n]+)",
        r"\*{1,2}Resolution\*{1,2}:?\s*([^\n\*]+)",
        r"\*{1,2}Remediation\*{1,2}:?\s*([^\n\*]+)",
        r"\*{1,2}Fix\*{1,2}:?\s*([^\n\*]+)",
    ]
    for p in patterns:
        m = re.search(p, text[:2000], re.IGNORECASE)
        if m:
            status = normalize_status(m.group(1))
            if status != Status.UNKNOWN:
                return status
    return Status.UNKNOWN


def _extract_description_block(text: str, header_line: str) -> str:
    """
    Extract the main description/body of a finding.
    Captures everything after the header up to the first labeled subsection.
    """
    # Remove the header line itself
    body = text[len(header_line):].lstrip()

    # Find where the first labeled section starts
    label_start = re.search(
        r"\n\*{1,2}(?:Description|Summary|Detail|Root Cause|Impact|Recommendation|"
        r"Proof of Concept|PoC|Attack|Severity|Status|Resolution|Mitigation|"
        r"Finding ID|Difficulty|Type|Likelihood|References?)\*{1,2}:?",
        body, re.IGNORECASE
    )

    if label_start:
        return body[:label_start.start()].strip()

    # No labels — take first big paragraph
    paragraphs = re.split(r"\n{2,}", body)
    if paragraphs:
        return paragraphs[0].strip()

    return ""


def _split_labeled_sections(text: str) -> dict[str, str]:
    """
    Split a finding section into labeled fields.
    Returns dict of {label_lower: content}.
    """
    # Match **Label:** or Label: followed by content
    section_pattern = re.compile(
        r"\*{0,2}([\w ]+?)\*{0,2}\s*:\s*(.*?)(?=\n\*{0,2}[\w ]+\*{0,2}\s*:|$)",
        re.DOTALL
    )
    fields: dict[str, str] = {}
    for m in section_pattern.finditer(text):
        key = m.group(1).strip().lower()
        val = m.group(2).strip()
        if key and val and len(key) < 50:
            fields[key] = val
    return fields


# ─── Main Extractor for One Section ──────────────────────────────────────────

def extract_finding_from_section(section_text: str) -> Optional[Finding]:
    """
    Parse a single finding section into a Finding object.
    Extracts ALL available fields — nothing is dropped.
    """
    if not section_text.strip():
        return None

    lines = section_text.split("\n")
    header_line = lines[0] if lines else ""

    finding = Finding()
    finding.raw_section = section_text

    # ── ID ──────────────────────────────────────────────────────────────────
    finding.finding_id = _extract_id_from_header(header_line)

    # ── Title ────────────────────────────────────────────────────────────────
    # Strip markdown heading markers and ID prefix
    title = re.sub(r"^#{1,6}\s*", "", header_line).strip()
    title = re.sub(r"\[{1,2}[CHMLIG]-\d+\]{1,2}:?\s*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"TOB-[A-Z]+-\d+[:\s]*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"HAL-\d+[:\s]*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"SCP-[A-Z]+-\d+[:\s]*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"\s+\[(?:Critical|High|Medium|Low|Info|Gas)\]", "", title, flags=re.IGNORECASE)
    title = re.sub(r"^\d+\.\s*", "", title)
    finding.title = title.strip().strip("*").strip()

    # ── Severity ─────────────────────────────────────────────────────────────
    finding.severity = _extract_severity_from_text(section_text, header_line)

    # ── Status ───────────────────────────────────────────────────────────────
    finding.status = _extract_status(section_text)

    # ── Description / Summary ────────────────────────────────────────────────
    description = (
        _extract_field(section_text, "Description", "Summary", "Details", "Vulnerability Detail",
                       "Detail", "Vulnerability", "Issue Description") or
        _extract_description_block(section_text, header_line)
    )
    finding.description = description

    # ── Root Cause ───────────────────────────────────────────────────────────
    finding.root_cause = _extract_field(
        section_text, "Root Cause", "Root cause", "Cause", "Technical Detail",
        "Technical Details", "Technical Description"
    )

    # ── Impact ───────────────────────────────────────────────────────────────
    finding.impact = _extract_field(
        section_text, "Impact", "Risk", "Risk Description",
        "Potential Impact", "Consequence"
    )

    # ── Likelihood ───────────────────────────────────────────────────────────
    finding.likelihood = _extract_field(
        section_text, "Likelihood", "Difficulty", "Exploitability"
    )

    # ── Proof of Concept ─────────────────────────────────────────────────────
    finding.proof_of_concept = _extract_field(
        section_text, "Proof of Concept", "PoC", "Proof-of-Concept",
        "Attack Scenario", "Exploit", "Steps to Reproduce"
    )
    finding.attack_scenario = _extract_field(
        section_text, "Attack Scenario", "Attack Vector", "Exploit Scenario",
        "Scenario"
    )

    # ── Recommendation / Fix ─────────────────────────────────────────────────
    finding.recommendation = _extract_field(
        section_text,
        "Recommendation", "Recommendations", "Mitigation",
        "Remediation", "Suggested Fix", "Fix", "Resolution",
        "How to Fix", "Proposed Fix"
    )
    finding.fix_description = _extract_field(
        section_text, "Fix Applied", "Fix Description", "Resolution Applied",
        "Applied Fix", "Patch", "Change"
    )

    # ── Code Snippets ─────────────────────────────────────────────────────────
    all_code = extract_code_blocks(section_text)

    # Heuristic: code snippets before "Recommendation" are vulnerable, after are fixed
    rec_pos = -1
    for marker in ["Recommendation", "Mitigation", "Fix", "Remediation", "Resolution"]:
        pos = section_text.lower().find(marker.lower())
        if pos > 0:
            rec_pos = pos
            break

    for snippet in all_code:
        # Find position of this snippet in text
        code_pos = section_text.find(snippet.code[:50]) if len(snippet.code) > 50 else -1
        if rec_pos > 0 and code_pos > rec_pos:
            finding.fixed_code.append(snippet)
        else:
            finding.vulnerable_code.append(snippet)

    # ── File / Contract References ────────────────────────────────────────────
    contracts, functions, line_refs = extract_file_refs(section_text)
    finding.affected_contracts = contracts
    finding.affected_functions = functions
    finding.affected_lines = line_refs

    # ── Finding Type ──────────────────────────────────────────────────────────
    finding_type = _extract_field(
        section_text, "Type", "Category", "Vulnerability Type", "Class"
    )
    finding.finding_type = finding_type

    # ── Tags ─────────────────────────────────────────────────────────────────
    finding.tags = detect_tags(section_text)

    # ── AI Check Points ───────────────────────────────────────────────────────
    finding.check_points = generate_check_points(finding)

    # Validate: must have at minimum a title or description
    if not finding.title and not finding.description:
        return None

    return finding


# ─── Full Report Parser ───────────────────────────────────────────────────────

def parse_markdown(path: Path, text: Optional[str] = None) -> tuple[str, list[Finding]]:
    """
    Parse a markdown/text audit report.
    Returns (raw_full_text, list_of_findings).
    """
    if text is None:
        text = path.read_text(encoding="utf-8", errors="ignore")

    sections = split_into_finding_sections(text)

    findings: list[Finding] = []
    for section in sections:
        finding = extract_finding_from_section(section)
        if finding:
            findings.append(finding)

    return text, findings
