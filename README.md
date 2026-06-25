# AuditTool — Smart Contract Audit Report Extractor

A local, AI-free Python CLI tool to parse, extract, and condense Smart Contract Audit Reports (PDF, Markdown, HTML, Text). It extracts every vulnerability finding in full detail, identifies vulnerable and fixed code snippets, and creates an easy-to-search structured JSON database and detailed Markdown reports.

## Features

- **No AI API Required**: Runs entirely locally using smart parsing and heuristics.
- **Multiple Formats**: Extracts text and structure from PDFs, Markdown, HTML, and Text reports.
- **Multi-Auditor Support**: Understands report formats from Code4rena, Sherlock, Trail of Bits, OpenZeppelin, Cantina, Spearbit, Cyfrin, Sigma Prime, Halborn, ConsenSys, and more.
- **Comprehensive Extraction**: Captures Severity, Status, Tags, Root Cause, Impact, Vulnerable Code, Proof of Concept, Recommendation, Fixed Code, and auto-generates "Check points" for future audits.
- **Aggregated View**: Process a whole directory of reports to create one master database of historical findings.

## Installation

AuditTool is built as a Python package. Use a virtual environment.

```bash
# Set up a virtual environment
python -m venv venv
source venv/bin/activate

# Install the tool
pip install -e .
```

Dependencies installed automatically: `click`, `pdfplumber`, `pymupdf` (fitz), `beautifulsoup4`.

## Usage

AuditTool provides a rich CLI with commands to `extract`, `list`, `show`, and `summary`.

### Extract Findings

Parse a single report or an entire directory of reports.

```bash
# Extract a single PDF report
audittool extract ./sample_report.pdf

# Extract all reports in a directory
# Saves aggregated findings to ./output/all_findings.json
audittool extract ./my_reports_dir/ --output ./output/

# Show findings on the terminal as they are extracted
audittool extract ./my_reports_dir/ --show-findings

# Filter by severity during extraction (e.g., only High & Critical)
audittool extract ./my_reports_dir/ --severity high
```

The output will contain:
- `{report_name}.json`: Structured data for the report.
- `{report_name}_report.md`: A beautifully formatted Markdown report.
- `all_findings.json` & `all_findings_report.md` (when processing a directory).

### View Extracted Data

Once you have an extracted JSON file, you can query it:

```bash
# List all findings in a summary table
audittool list ./output/all_findings.json

# Filter list by severity and tags
audittool list ./output/all_findings.json --severity high --tag reentrancy

# Show full detail of a specific finding (e.g., ID: H-01)
audittool show ./output/all_findings.json H-01

# Print a high-level summary of the database
audittool summary ./output/all_findings.json
```

## How It Works

1. **Format Detection**: Checks file magic bytes and extensions to determine if a file is PDF, MD, HTML, or TXT.
2. **Text Extraction**: 
   - *PDF*: Uses `pdfplumber` to extract text preserving layout and tables. Falls back to `pymupdf`.
   - *HTML*: Uses `beautifulsoup4` to strip tags but keep headings, lists, and code blocks (`<pre>`/`<code>`).
3. **Auditor Fingerprinting**: Scans the text for known keywords and regex patterns to identify the auditing firm (e.g., `\[H-\d+\]` for Code4rena).
4. **Section Splitting**: Uses complex regex heuristics to chunk the report into individual finding sections.
5. **Field Extraction**: For each section, it searches for labeled fields (`**Description:**`, `### Vulnerability Detail`) and code blocks to populate a comprehensive `Finding` object.

## Development

The code is organized as follows:
- `audittool/models.py`: Data structures (`Finding`, `AuditReport`).
- `audittool/detector.py`: Heuristics for finding auditor style, project name, etc.
- `audittool/parsers/`: Format-specific text extractors.
- `audittool/parsers/markdown_parser.py`: The core logic that chunks text and extracts finding fields.
- `audittool/extractor.py`: High-level orchestration.
- `audittool/reporter.py`: Terminal and Markdown output generation.
- `audittool/cli.py`: Click CLI implementation.
# audit-tool
