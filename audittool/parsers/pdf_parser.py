"""
PDF parser — extracts text from audit report PDFs.
Uses pdfplumber (primary) with pymupdf fallback.
Preserves structure: headings, code blocks, tables.
"""

from __future__ import annotations
from pathlib import Path


def parse_pdf(path: Path) -> str:
    """
    Extract all text from a PDF file.
    Tries pdfplumber first, falls back to pymupdf (fitz).
    Returns raw text preserving paragraph structure.
    """
    text = _try_pdfplumber(path)
    if text and len(text.strip()) > 200:
        return text

    text = _try_pymupdf(path)
    if text and len(text.strip()) > 200:
        return text

    raise RuntimeError(
        f"Could not extract readable text from PDF: {path}\n"
        "Install pdfplumber or pymupdf: pip install pdfplumber pymupdf"
    )


def _try_pdfplumber(path: Path) -> str:
    """Extract text using pdfplumber."""
    try:
        import pdfplumber
    except ImportError:
        return ""

    pages_text: list[str] = []
    try:
        with pdfplumber.open(str(path)) as pdf:
            for page in pdf.pages:
                # Extract text with layout preservation
                text = page.extract_text(x_tolerance=3, y_tolerance=3)
                if text:
                    pages_text.append(text)

                # Also try to extract tables
                tables = page.extract_tables()
                for table in tables:
                    for row in table:
                        if row:
                            row_text = " | ".join(
                                (cell or "").strip() for cell in row if cell
                            )
                            if row_text.strip():
                                pages_text.append(row_text)

    except Exception as e:
        return ""

    return "\n\n".join(pages_text)


def _try_pymupdf(path: Path) -> str:
    """Extract text using PyMuPDF (fitz)."""
    try:
        import fitz  # pymupdf
    except ImportError:
        return ""

    pages_text: list[str] = []
    try:
        doc = fitz.open(str(path))
        for page in doc:
            # Get text in 'blocks' mode for better structure
            blocks = page.get_text("dict")["blocks"]
            page_lines: list[str] = []
            for block in blocks:
                if block.get("type") == 0:  # text block
                    for line in block.get("lines", []):
                        line_text = " ".join(
                            span.get("text", "") for span in line.get("spans", [])
                        )
                        if line_text.strip():
                            page_lines.append(line_text)
            pages_text.append("\n".join(page_lines))
        doc.close()
    except Exception:
        return ""

    return "\n\n".join(pages_text)
