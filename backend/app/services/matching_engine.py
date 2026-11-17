"""
Matching Engine — Exact match between CVE affected_products and client inventory.

Uses synchronous psycopg2 because it is called from Scrapy's DatabasePipeline
(Twisted event loop, not asyncio).

Rules:
- Vendor match: exact, case-insensitive
- Product family match: exact, case-insensitive
- Version match: if both sides have versions, check range; if either is empty, partial match
- No fuzzy matching, no guessing — 0 matches is better than a wrong match
"""

import json
import re
import logging

logger = logging.getLogger(__name__)


def match_clients_for_cve(affected_products: list, conn) -> list[dict]:
    """
    Exact match: compare CVE's affected_products against all active clients with inventory.

    affected_products format (from enrichment_data):
    [{"vendor": "Fortinet", "product_family": "FortiGate", "versions": ["7.4.0 through 7.4.8"]}]

    Returns list of:
    {
        "client_id": int,
        "client_name": str,
        "client_email": str,
        "company": str,
        "confidence": "high" | "partial",
        "reason": str
    }
    """
    if not affected_products:
        return []

    # Fetch all active clients with non-empty inventory
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, full_name, email, company, inventory
            FROM notification_recipients
            WHERE role IN ('CLIENT', 'NOT_CONCERNED')
              AND is_active = true
              AND inventory IS NOT NULL
              AND inventory != '[]'::jsonb
        """)
        clients = cur.fetchall()

    if not clients:
        return []

    matches = []
    matched_ids = set()

    for client_id, client_name, client_email, company, inventory_json in clients:
        # inventory_json is already a Python list (psycopg2 auto-parses JSONB)
        inventory = inventory_json if isinstance(inventory_json, list) else json.loads(inventory_json or "[]")

        best_confidence = None
        best_reason = ""

        for ap in affected_products:
            ap_vendor = (ap.get("vendor") or "").lower()
            ap_family = (ap.get("product_family") or ap.get("name") or "").lower()
            ap_versions = ap.get("versions") or []
            # Versions may be a joined string after normalization — split back to list
            if isinstance(ap_versions, str):
                ap_versions = [v.strip() for v in ap_versions.split(";") if v.strip()]

            for inv_item in inventory:
                inv_vendor = (inv_item.get("vendor") or "").lower()
                inv_family = (inv_item.get("product_family") or "").lower()
                inv_version = (inv_item.get("version") or "").strip()

                # Exact vendor match
                if ap_vendor != inv_vendor:
                    continue

                # Exact product family match
                if ap_family != inv_family:
                    continue

                # Product matched — now check versions
                if not ap_versions or not inv_version:
                    # One side has no version info → partial match
                    if best_confidence != "high":
                        best_confidence = "partial"
                        product_raw = inv_item.get("product_raw", ap.get("product_raw", ""))
                        best_reason = f"Product match ({product_raw}), version unknown"
                else:
                    # Both have versions — check if client version falls in affected range
                    if version_in_range(inv_version, ap_versions):
                        best_confidence = "high"
                        product_raw = inv_item.get("product_raw", ap.get("product_raw", ""))
                        best_reason = f"Exact match: {product_raw} {inv_version} in affected range"

            if best_confidence == "high":
                break  # No need to check more products

        if best_confidence and client_id not in matched_ids:
            matched_ids.add(client_id)
            matches.append({
                "client_id": client_id,
                "client_name": client_name,
                "client_email": client_email,
                "company": company or "",
                "confidence": best_confidence,
                "reason": best_reason,
            })

    return matches


def version_in_range(client_version: str, affected_versions: list[str]) -> bool:
    """
    Check if client_version falls within any of the affected_versions strings.
    Handles formats:
    - "7.4.0 through 7.4.8"
    - "before 7.4.9"
    - "7.4.x" (wildcard)

    Returns False if parsing fails — do not guess.
    """
    client_parts = _parse_version(client_version)
    if client_parts is None:
        return False

    for av in affected_versions:
        av = av.strip().lower()

        # "X through Y" or "X to Y"
        m = re.match(r'([\d.]+)\s+(?:through|to)\s+([\d.]+)', av)
        if m:
            low = _parse_version(m.group(1))
            high = _parse_version(m.group(2))
            if low is not None and high is not None:
                # Pad all tuples to the same length with zeros before comparing
                n = max(len(client_parts), len(low), len(high))
                cp = _pad(client_parts, n)
                lp = _pad(low, n)
                hp = _pad(high, n)
                if lp <= cp <= hp:
                    return True
            continue

        # "before X" or "< X"
        m = re.match(r'(?:before|<)\s*([\d.]+)', av)
        if m:
            threshold = _parse_version(m.group(1))
            if threshold is not None:
                n = max(len(client_parts), len(threshold))
                if _pad(client_parts, n) < _pad(threshold, n):
                    return True
            continue

        # "X.x" or "X.*" wildcard
        m = re.match(r'([\d.]+)\.[x*]$', av)
        if m:
            prefix = _parse_version(m.group(1))
            if prefix is not None and client_parts[:len(prefix)] == prefix:
                return True
            continue

        # Exact version match (pad to same length)
        exact = _parse_version(av)
        if exact is not None:
            n = max(len(client_parts), len(exact))
            if _pad(client_parts, n) == _pad(exact, n):
                return True

    return False


def _pad(t: tuple, length: int) -> tuple:
    """Pad a version tuple with trailing zeros to reach the given length."""
    return t + (0,) * (length - len(t))


def _parse_version(version_str: str):
    """
    Parse a version string into a tuple of ints for comparison.
    Returns None if unparseable.
    """
    if not version_str:
        return None
    # Strip leading 'v'
    version_str = version_str.strip().lstrip("vV")
    # Extract numeric parts
    parts = re.findall(r'\d+', version_str)
    if not parts:
        return None
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return None
