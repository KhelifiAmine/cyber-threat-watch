"""
Scraper utilities — shared helpers for spider text extraction.
"""

import re


def extract_structured_text(container):
    """
    Extract text from a parsel Selector container, preserving paragraph
    and bullet-point structure.

    Returns a string with:
      - Paragraphs separated by \\n\\n
      - Bullet points as \\n- item

    Usage in spiders:
        section = response.css("div.article-content")
        if section:
            body = extract_structured_text(section[0])
    """
    if container is None:
        return ""

    blocks = []

    for el in container.css("p, ul, ol, h2, h3, h4, li"):
        tag = el.root.tag if hasattr(el.root, "tag") else ""

        if tag in ("ul", "ol"):
            items = el.css("li")
            for li in items:
                text = _inline_text(li)
                if text:
                    blocks.append(f"- {text}")

        elif tag == "li":
            # Skip standalone li — already handled inside ul/ol above.
            # Only process if it's a direct child of the container (no ul/ol parent).
            parent = el.root.getparent()
            if parent is not None and parent.tag in ("ul", "ol"):
                continue
            text = _inline_text(el)
            if text:
                blocks.append(f"- {text}")

        elif tag in ("h2", "h3", "h4"):
            text = _inline_text(el)
            if text:
                blocks.append(text)

        else:
            # p tag
            text = _inline_text(el)
            if text:
                blocks.append(text)

    return "\n\n".join(blocks)


def _inline_text(selector):
    """Extract all inline text from a selector, joining fragments into one line."""
    parts = selector.css("::text").getall()
    text = " ".join(p.strip() for p in parts if p.strip())
    # Collapse internal whitespace but preserve the single string
    text = re.sub(r"\s+", " ", text).strip()
    return text
