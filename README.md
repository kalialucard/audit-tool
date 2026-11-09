# AuditTool 🔍

> Parse smart contract audit reports (PDF, Markdown, HTML, TXT) into structured JSON and Markdown — locally, without any AI API.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Formats](https://img.shields.io/badge/formats-PDF%20%7C%20MD%20%7C%20HTML%20%7C%20TXT-orange)]()

## What It Does

AuditTool extracts every finding from smart contract audit reports — severity, status, root cause, impact, vulnerable code snippet, PoC, recommendation, and fixed code — into a structured, queryable database you can diff, grep, and build tooling on top of.

**Supported audit firms:** Code4rena, Sherlock, Trail of Bits, OpenZeppelin, Cantina, Spearbit, Cyfrin, Sigma Prime, Halborn, ConsenSys, and more.

## Screenshot

<!-- TODO: add a screenshot of `audittool list` tabular output here -->
![AuditTool list output](docs/screenshot.png)

## Installation

```bash
git clone https://github.com/kalialucard/audit-tool.git
cd audit-tool

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -e .
# Installs: click, pdfplumber, pymupdf, beautifulsoup4
```

## Usage

### Extract findings from a report

```bash
# Single PDF
audittool extract ./report.pdf

# Entire directory (creates all_findings.json + per-report JSONs)
audittool extract ./reports/ --output ./output/

# Show findings as they're parsed
audittool extract ./reports/ --show-findings

# Filter to High and Critical only
audittool extract ./reports/ --severity high
```

### Query extracted findings

```bash
# Summary table of all findings
audittool list ./output/all_findings.json

# Filter by severity and tag
audittool list ./output/all_findings.json --severity high --tag reentrancy

# Full detail for finding H-01
audittool show ./output/all_findings.json H-01

# High-level stats
audittool summary ./output/all_findings.json
```

### Output structure

```
output/
├── report_name.json           # Per-report structured findings
├── report_name_report.md      # Formatted Markdown report
├── all_findings.json          # Aggregated database
└── all_findings_report.md
```

## How It Works

1. **Format detection** — magic bytes + extension → routes to the right parser
2. **Auditor fingerprinting** — regex patterns identify the audit firm (e.g., `[H-\d+]` for Code4rena)
3. **Section splitting** — chunks the document into individual finding sections
4. **Field extraction** — pulls `Severity`, `Status`, `Root Cause`, `Impact`, `PoC`, `Recommendation`, `Fixed Code` per finding

## Project Structure

```
audit-tool/
├── audittool/
│   ├── cli.py              # Click CLI
│   ├── extractor.py        # Orchestration
│   ├── detector.py         # Auditor fingerprinting
│   ├── reporter.py         # Markdown + terminal output
│   ├── models.py           # Finding / AuditReport dataclasses
│   └── parsers/            # PDF, HTML, Markdown, text parsers
└── pyproject.toml
```

## Contributing

PRs welcome. Open an issue for large changes.

## License

[MIT](LICENSE) © kalialucard
