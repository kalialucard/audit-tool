"""
HTML parser — extracts text from HTML audit reports.
Uses BeautifulSoup to preserve structure and extract code blocks.
"""

from __future__ import annotations
from pathlib import Path
import re


def parse_html(path: Path) -> str:
    """
    Extract readable text from an HTML audit report.
    Preserves headings, code blocks, and list structure.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        raise ImportError(
            "beautifulsoup4 is required for HTML parsing.\n"
            "Install with: pip install beautifulsoup4"
        )

    content = path.read_text(encoding="utf-8", errors="ignore")
    soup = BeautifulSoup(content, "html.parser")

    # Remove script/style/nav/footer noise
    for tag in soup.find_all(["script", "style", "nav", "footer", "header"]):
        tag.decompose()

    lines: list[str] = []
    _walk_node(soup.body or soup, lines)

    text = "\n".join(lines)
    # Clean excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _walk_node(node, lines: list[str]) -> None:
    """Recursively walk HTML nodes and build text with markdown-like structure."""
    from bs4 import NavigableString, Tag

    if isinstance(node, NavigableString):
        return  # handled by parent

    tag = node.name if hasattr(node, "name") else None

    if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
        level = int(tag[1])
        text = node.get_text(separator=" ", strip=True)
        if text:
            lines.append("\n" + "#" * level + " " + text)

    elif tag in ("pre", "code"):
        code = node.get_text()
        if tag == "pre":
            lines.append("\n```\n" + code.rstrip() + "\n```")
        else:
            parent_tag = node.parent.name if node.parent else ""
            if parent_tag != "pre":
                lines.append("`" + code.strip() + "`")

    elif tag in ("p", "div", "section", "article"):
        text = node.get_text(separator=" ", strip=True)
        # Check if it's just wrapper — recurse deeper
        has_block_children = any(
            getattr(child, "name", None) in (
                "p", "div", "h1", "h2", "h3", "h4", "h5", "h6",
                "ul", "ol", "table", "pre", "blockquote"
            )
            for child in node.children
        )
        if has_block_children:
            for child in node.children:
                _walk_node(child, lines)
        else:
            if text:
                lines.append(text)

    elif tag in ("ul", "ol"):
        for i, li in enumerate(node.find_all("li", recursive=False)):
            prefix = "- " if tag == "ul" else f"{i+1}. "
            text = li.get_text(separator=" ", strip=True)
            if text:
                lines.append(prefix + text)

    elif tag == "table":
        rows = node.find_all("tr")
        for row in rows:
            cells = row.find_all(["th", "td"])
            row_text = " | ".join(c.get_text(separator=" ", strip=True) for c in cells)
            if row_text.strip():
                lines.append(row_text)

    elif tag == "blockquote":
        for child in node.children:
            text = child.get_text(separator=" ", strip=True) if hasattr(child, "get_text") else str(child).strip()
            if text:
                lines.append("> " + text)

    elif tag in ("strong", "b", "em", "i", "span", "a"):
        # Inline — handled by parent's get_text
        pass

    elif tag in ("br", "hr"):
        lines.append("")

    else:
        # Generic — recurse
        for child in node.children:
            _walk_node(child, lines)
