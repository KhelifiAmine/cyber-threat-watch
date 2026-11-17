"""
Inventory Excel Parser — Reads Vendor/Product/Version Excel sheets
into structured inventory entries.

Handles:
- Merged vendor cells (forward-fill blank vendor cells)
- Multi-line version cells (split on newline or semicolon)
- Automatic header row detection
- Normalizes vendor and product_family via product_aliases
"""

import io
import re

from app.services.product_aliases import normalize_vendor, normalize_product_family


def parse_inventory_excel(file_bytes: bytes) -> list[dict]:
    """
    Parse a Vendor/Product/Version Excel sheet into a structured inventory list.

    Returns list of:
    {
        "vendor_raw": str,
        "product_raw": str,
        "vendor": str,           # normalized, or vendor_raw if not in alias map
        "product_family": str,   # normalized, or product_raw if not in alias map
        "version": str
    }

    Raises ValueError if no recognizable header row is found.
    """
    import openpyxl

    wb = openpyxl.load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
    ws = wb.active

    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        raise ValueError("Excel file is empty.")

    # Detect header row — look within the first 5 rows for vendor/product/version
    header_idx = None
    col_vendor = None
    col_product = None
    col_version = None

    for i, row in enumerate(rows[:5]):
        cells = [str(c).strip().lower() if c else "" for c in row]
        v_idx = _find_col(cells, ("vendor", "manufacturer", "fabricant"))
        p_idx = _find_col(cells, ("product", "produit", "software", "hardware", "application"))
        ver_idx = _find_col(cells, ("version", "ver", "release"))

        if v_idx is not None and p_idx is not None:
            header_idx = i
            col_vendor = v_idx
            col_product = p_idx
            col_version = ver_idx
            break

    if header_idx is None:
        raise ValueError(
            "Could not detect Vendor/Product/Version columns. "
            "Ensure the header row contains 'Vendor' and 'Product' column names."
        )

    entries = []
    last_vendor = ""

    for row in rows[header_idx + 1:]:
        # Safely extract cell values
        vendor_raw = _cell_str(row, col_vendor)
        product_raw = _cell_str(row, col_product)
        version_raw = _cell_str(row, col_version) if col_version is not None else ""

        # Forward-fill vendor from merged cells
        if vendor_raw:
            last_vendor = vendor_raw
        else:
            vendor_raw = last_vendor

        # Skip empty rows
        if not product_raw and not version_raw:
            continue
        if not product_raw:
            continue

        # Normalize vendor
        vendor_normalized = normalize_vendor(vendor_raw)
        if not vendor_normalized:
            vendor_normalized = vendor_raw.strip()

        # Normalize product family
        product_family = normalize_product_family(vendor_normalized, product_raw)
        if not product_family:
            product_family = product_raw.strip()

        # Handle multi-line or semicolon-separated versions
        versions = _split_versions(version_raw) if version_raw else [""]

        for ver in versions:
            entries.append({
                "vendor_raw": vendor_raw.strip(),
                "product_raw": product_raw.strip(),
                "vendor": vendor_normalized,
                "product_family": product_family,
                "version": ver.strip(),
            })

    wb.close()
    return entries


def _find_col(cells, keywords):
    """Find the first column index whose cell content matches any keyword."""
    for i, cell in enumerate(cells):
        for kw in keywords:
            if kw in cell:
                return i
    return None


def _cell_str(row, idx):
    """Safely get a cell value as a stripped string."""
    if idx is None or idx >= len(row):
        return ""
    val = row[idx]
    if val is None:
        return ""
    return str(val).strip()


def _split_versions(version_str):
    """Split a version cell by newline, semicolon, or comma (if it looks like a list)."""
    if not version_str:
        return [""]
    # Split on newlines first
    parts = re.split(r'[\n\r]+', version_str)
    # If only one part, try semicolons
    if len(parts) == 1:
        parts = parts[0].split(";")
    # Filter out empty parts
    parts = [p.strip() for p in parts if p.strip()]
    return parts if parts else [""]


# ── Company/Email header block (for the "general drop creates a client" flow) ──

_COMPANY_LABELS = ("company", "société", "societe", "entreprise", "organisation", "organization")
_EMAIL_LABELS = ("email", "e-mail", "courriel")
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _after_colon(s: str) -> str:
    return s.split(":", 1)[1].strip() if ":" in s else ""


def _scan_meta(rows):
    """Scan rows for a 'Company:' / 'Email:' header block. The label may be in one
    cell with the value after ':' or in the adjacent cell; a bare email cell is
    also accepted. Returns (company_or_None, email_or_None)."""
    company = email = None
    for row in rows:
        cells = [str(c).strip() if c is not None else "" for c in row]
        for i, cell in enumerate(cells):
            low = cell.lower()
            if company is None and any(low.startswith(lbl) for lbl in _COMPANY_LABELS):
                val = _after_colon(cell) or (cells[i + 1].strip() if i + 1 < len(cells) else "")
                if val and "@" not in val:
                    company = val
            if email is None and any(lbl in low for lbl in _EMAIL_LABELS):
                m = _EMAIL_RE.search(_after_colon(cell) or (cells[i + 1] if i + 1 < len(cells) else ""))
                if m:
                    email = m.group(0).lower()
            if email is None and _EMAIL_RE.fullmatch(cell):
                email = cell.lower()
    return company, email


def parse_client_inventory_excel(file_bytes: bytes) -> dict:
    """Parse a client inventory sheet that may carry a Company/Email header block
    above the Vendor/Product/Version table.

    Returns {"company": str|None, "email": str|None, "entries": [...]} where each
    entry has the same shape as parse_inventory_excel() returns.
    """
    import openpyxl

    wb = openpyxl.load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        raise ValueError("Excel file is empty.")

    # Detect the Vendor/Product header row within the first 12 rows.
    header_idx = col_vendor = col_product = col_version = None
    for i, row in enumerate(rows[:12]):
        cells = [str(c).strip().lower() if c else "" for c in row]
        v_idx = _find_col(cells, ("vendor", "manufacturer", "fabricant"))
        p_idx = _find_col(cells, ("product", "produit", "software", "hardware", "application"))
        if v_idx is not None and p_idx is not None:
            header_idx = i
            col_vendor, col_product = v_idx, p_idx
            col_version = _find_col(cells, ("version", "ver", "release"))
            break

    # Company/Email live in the block above the table (or anywhere if no table).
    company, email = _scan_meta(rows[:header_idx] if header_idx is not None else rows)

    entries = []
    if header_idx is not None:
        last_vendor = ""
        for row in rows[header_idx + 1:]:
            vendor_raw = _cell_str(row, col_vendor)
            product_raw = _cell_str(row, col_product)
            version_raw = _cell_str(row, col_version) if col_version is not None else ""
            if vendor_raw:
                last_vendor = vendor_raw
            else:
                vendor_raw = last_vendor
            if not product_raw:
                continue
            vendor_normalized = normalize_vendor(vendor_raw) or vendor_raw.strip()
            product_family = normalize_product_family(vendor_normalized, product_raw) or product_raw.strip()
            for ver in (_split_versions(version_raw) if version_raw else [""]):
                entries.append({
                    "vendor_raw": vendor_raw.strip(),
                    "product_raw": product_raw.strip(),
                    "vendor": vendor_normalized,
                    "product_family": product_family,
                    "version": ver.strip(),
                })
    wb.close()
    return {"company": company, "email": email, "entries": entries}
