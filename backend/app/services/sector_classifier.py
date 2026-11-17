"""
Sector classifier — keyword-based sector detection for threats, CVEs, and news.

Used by: dashboard sectors endpoint, news pipeline, report generation.
"""

SECTOR_KEYWORDS = {
    "Banking & Finance": [
        "bank", "banking", "finance", "financial", "swift", "payment",
        "fintech", "insurance", "credit", "trading", "stock", "forex",
    ],
    "Energy & Utilities": [
        "energy", "oil", "gas", "power", "electricity", "utility",
        "grid", "scada", "ics", "nuclear", "solar", "wind",
    ],
    "Healthcare": [
        "health", "hospital", "medical", "clinical", "patient",
        "pharmacy", "dicom", "hl7", "vaccine", "pharmaceutical",
    ],
    "Telecom": [
        "telecom", "telco", "carrier", "mobile", "5g", "broadband",
        "isp", "lte", "wireless", "cellular",
    ],
    "Government": [
        "government", "public sector", "ministry", "agency", "federal",
        "municipal", "defence", "defense", "military", "homeland",
    ],
    "Manufacturing": [
        "manufacturing", "industrial", "factory", "automotive",
        "aerospace", "assembly", "production",
    ],
    "Retail": [
        "retail", "e-commerce", "ecommerce", "point of sale", "pos",
        "supply chain", "merchant",
    ],
    "Education": [
        "education", "university", "school", "academic", "research",
        "campus", "student",
    ],
    "Transportation": [
        "transport", "logistics", "aviation", "maritime", "railway",
        "airport", "shipping", "fleet",
    ],
    "Technology": [
        "software", "cloud", "saas", "microsoft", "cisco", "fortinet",
        "vmware", "oracle", "google", "amazon", "aws", "azure",
    ],
}

SECTORS_LIST = list(SECTOR_KEYWORDS.keys())


def infer_sectors(text: str, product_names: list[str] | None = None) -> list[str]:
    """Return list of sector names detected in the given text."""
    combined = text.lower()
    if product_names:
        combined += " " + " ".join(p.lower() for p in product_names)
    matched = []
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            matched.append(sector)
    return matched
