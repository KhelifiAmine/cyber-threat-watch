"""
LLM Enrichment Service — phi3.5 via Ollama

Source-aware prompt routing: three paths based on source type.
  Path 1 (Structured): NVD, GitHub, Microsoft, Cisco, FortiGuard — summary only
  Path 2 (Unstructured): CERT-EU, CERT-FR — JSON extraction (regions, products) + summary
  Path 3 (News): darkreading, securityweek, etc. — summary + sectors

Returns empty lists for all fields on any failure (Ollama down, timeout, bad parse).
"""

import json
import logging
import os
import re
import time
import urllib.request

import redis as redis_lib

logger = logging.getLogger(__name__)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
MODEL = os.getenv("OLLAMA_MODEL", "phi3.5")
# Pin the context window. phi3.5 advertises a 128K context; left unset, recent
# Ollama versions size the KV cache for the full 128K and refuse to load
# ("model requires more system memory (46.9 GiB)..."). The enrichment inputs are
# capped well under this, so a small window is both sufficient and memory-safe.
NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "4096"))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ── LLM lock: serialize all Ollama calls across spider subprocesses ──
_LLM_LOCK_KEY = "llm:call_lock"
_LLM_LOCK_TTL = 300       # auto-release after 5 min (safety net if process dies)
_LLM_LOCK_POLL = 2        # seconds between retry attempts

# ── VRAM reset: unload model every N calls to prevent degradation ──
_LLM_CALL_COUNTER_KEY = "llm:call_count"
_LLM_BATCH_SIZE = 15      # phi3.5 degrades around call 23; reset well before that


def _get_redis():
    return redis_lib.from_url(REDIS_URL, decode_responses=True)


def _acquire_llm_lock(r):
    """Block until the LLM lock is acquired. Returns a unique token for safe release."""
    token = f"{os.getpid()}:{time.time()}"
    while not r.set(_LLM_LOCK_KEY, token, nx=True, ex=_LLM_LOCK_TTL):
        time.sleep(_LLM_LOCK_POLL)
    return token


def _release_llm_lock(r, token):
    """Release the lock only if we still own it."""
    if r.get(_LLM_LOCK_KEY) == token:
        r.delete(_LLM_LOCK_KEY)


def _unload_model():
    """Unload phi3.5 from VRAM to reset model state. Next call auto-reloads it."""
    payload = json.dumps({"model": MODEL, "keep_alive": 0}).encode()
    req = urllib.request.Request(
        OLLAMA_URL + "/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        logger.info("[Enrichment] VRAM reset — model unloaded (batch limit reached)")
    except Exception as e:
        logger.warning(f"[Enrichment] VRAM reset failed: {e}")

# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------

_STRUCTURED_SOURCES = frozenset({
    "nvd", "github advisory", "microsoft msrc", "cisco psirt", "fortiguard",
})
_UNSTRUCTURED_SOURCES = frozenset({
    "cert-eu", "cert-fr",
})
_NEWS_SOURCES = frozenset({
    "darkreading", "securityweek", "bleepingcomputer", "thehackernews",
})


def _classify_source(source: str) -> str:
    """Return 'structured', 'unstructured', or 'news' based on source name."""
    s = (source or "").strip().lower()
    if s in _STRUCTURED_SOURCES:
        return "structured"
    if s in _UNSTRUCTURED_SOURCES:
        return "unstructured"
    if s in _NEWS_SOURCES:
        return "news"
    # Unknown sources default to unstructured (safest — full extraction)
    return "unstructured"


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_PROMPT_STRUCTURED = (
    "You are a security advisory analyst. The advisory may be in French or English. "
    "ALL output MUST be in English — translate any French text.\n\n"
    "Return ONLY a JSON object with exactly three fields:\n"
    "{\"summary\":\"\",\"impact_points\":[],\"remediation_steps\":[]}\n\n"
    "SUMMARY: A concise summary of the vulnerability — what it is, who is affected, "
    "and what is the risk. MAXIMUM 5 lines. Plain text, no bullet points.\n\n"
    "IMPACT_POINTS: list of impact statements (e.g. \"Remote code execution\", "
    "\"Elevation of privilege\", \"Information disclosure\"). Extract ONLY from the text.\n\n"
    "REMEDIATION_STEPS: list of remediation actions stated in the text "
    "(e.g. \"Apply security update KB5040442\", \"Upgrade to version 7.4.9\"). "
    "Leave [] if no specific remediation is mentioned.\n\n"
    "RULES:\n"
    "- Do NOT list products or versions — that data comes from the source.\n"
    "- Do NOT add recommendations, conclusions, or opinions.\n"
    "- Only state facts from the text. Do NOT use your training knowledge.\n"
    "- Return ONLY the JSON object. No extra text."
)

_PROMPT_UNSTRUCTURED_EXTRACT = (
    "You are a security data extractor. The advisory may be in French or English. "
    "ALL output values MUST be in English — translate any French text. "
    "Return ONLY the JSON object below. No explanation, no markdown, no extra text.\n\n"
    "{\"affected_products\":[{\"name\":\"\",\"versions\":\"\",\"notes\":\"\"}],"
    "\"affected_os\":[],\"affected_regions\":[],"
    "\"impact_points\":[],\"remediation_steps\":[],\"temp_mitigation\":[]}\n\n"
    "RULES:\n"
    "1. Extract ONLY what is explicitly written in the text. Translate French to English.\n"
    "2. Leave [] if the text does not state it. Do NOT guess or infer.\n"
    "3. affected_products: name without version numbers. Versions go in 'versions' field.\n"
    "   French headings like 'Systèmes affectés' list affected products — extract them.\n"
    "4. affected_os: ONLY operating systems explicitly named (Windows, Linux, macOS, Android).\n"
    "   Applications and libraries go in affected_products.\n"
    "5. affected_regions: ONLY if the text explicitly names targeted regions.\n"
    "   Use: Middle East, MENA, Europe, North America, Asia-Pacific, Africa, Latin America, Global.\n"
    "   Do NOT infer regions from organization names. Leave [] if none stated.\n"
    "6. remediation_steps: extract patch/update instructions from the text.\n"
    "7. impact_points: extract impact statements from the text.\n"
    "8. temp_mitigation: extract workaround steps. Leave [] if none.\n"
    "9. Do NOT add anything not written in the source text."
)

_PROMPT_UNSTRUCTURED_PROSE = (
    "You are a security advisory summarizer. The advisory may be in French or English. "
    "ALL output MUST be in English — translate any French text.\n\n"
    "Write a concise summary of this advisory. "
    "What is the threat, who is affected, and what is the risk.\n\n"
    "RULES:\n"
    "- MAXIMUM 5 lines. Up to 7 lines only if the advisory is very long.\n"
    "- Do NOT list products, versions, or remediation steps.\n"
    "- Do NOT add recommendations, conclusions, or opinions.\n"
    "- Do NOT output JSON, markdown, headers, or bullet points.\n"
    "- Only state facts from the text. Do NOT use your training knowledge.\n"
    "- Plain text only. Professional tone."
)

_PROMPT_NEWS = (
    "You are a cybersecurity news analyst. The article may be in French or English. "
    "ALL output MUST be in English — translate any French text.\n\n"
    "Return ONLY a JSON object with exactly three fields:\n"
    "{\"summary\":\"\",\"sectors\":[],\"regions\":[]}\n\n"
    "SUMMARY: A concise summary of the article — what happened and why it matters. "
    "MAXIMUM 5 lines. Plain text, no bullet points, no headers.\n\n"
    "SECTORS: list of industry sectors this article is relevant to. "
    "Choose ONLY from: Banking & Finance, Energy & Utilities, Healthcare, "
    "Telecom, Government, Manufacturing, Retail, Education, Transportation, Technology. "
    "Empty list [] if no specific industry is discussed.\n\n"
    "REGIONS: list of geographic regions explicitly mentioned as targets or affected areas. "
    "Choose ONLY from: Middle East, MENA, Europe, North America, Asia-Pacific, Africa, Latin America, Global. "
    "Empty list [] if no region is explicitly stated.\n\n"
    "RULES:\n"
    "- A sector is relevant ONLY if the article explicitly discusses that industry's "
    "organizations, infrastructure, or regulations.\n"
    "- NEVER assign Banking & Finance unless the article explicitly names a bank, "
    "financial institution, payment processor, or describes direct theft of money.\n"
    "- Do NOT infer regions from organization names — only use explicitly stated regions.\n"
    "- Do NOT add recommendations, conclusions, or opinions in the summary.\n"
    "- Only state facts from the article. Do NOT use your training knowledge.\n"
    "- Return ONLY the JSON object. No extra text."
)

# ---------------------------------------------------------------------------
# Empty enrichment shape — all paths return this structure
# ---------------------------------------------------------------------------

EMPTY_ENRICHMENT: dict = {
    "affected_os": [],
    "affected_products": [],
    "affected_regions": [],
    "impact_points": [],
    "remediation_steps": [],
    "temp_mitigation": [],
    "summary": "",
}

# ---------------------------------------------------------------------------
# Product normalization (shared)
# ---------------------------------------------------------------------------


def normalize_affected_products(raw_list: list) -> list:
    """
    Normalize affected_products from either spider format or LLM format
    into a unified shape that both the frontend and matching engine can use.

    Spider format:  {"vendor": "Fortinet", "product_raw": "FortiGate 7.4", "product_family": "FortiGate", "versions": [...]}
    LLM format:     {"name": "FortiGate", "versions": "7.4.0 through 7.4.8", "notes": "..."}
    Unified output: {"name": "FortiGate 7.4", "vendor": "Fortinet", "product_family": "FortiGate", "versions": "7.4.0 through 7.4.8", "notes": ""}
    """
    cleaned = []
    for entry in raw_list:
        if isinstance(entry, dict):
            name = str(entry.get("name") or entry.get("product_raw") or entry.get("product_family") or "").strip()
            versions = entry.get("versions", "")
            if isinstance(versions, list):
                versions = "; ".join(str(v) for v in versions if str(v).strip())
            versions = str(versions).strip()
            notes = str(entry.get("notes", "")).strip()
            vendor = str(entry.get("vendor", "")).strip()
            product_family = str(entry.get("product_family", "")).strip()
        else:
            name = str(entry).strip()
            versions = ""
            notes = ""
            vendor = ""
            product_family = ""
        if not name:
            continue
        product = {"name": name, "versions": versions, "notes": notes}
        if vendor:
            product["vendor"] = vendor
        if product_family:
            product["product_family"] = product_family
        cleaned.append(product)
    return cleaned


# ---------------------------------------------------------------------------
# JSON cleanup helpers
# ---------------------------------------------------------------------------

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_MARKDOWN_PREFIX_RE = re.compile(r"^(?:\*\*|#{1,3}\s*)", re.MULTILINE)


def _first_balanced_object(s: str) -> str:
    """Return the first balanced {...} substring, respecting string literals."""
    depth = 0
    start = -1
    in_str = False
    escape = False
    for i, ch in enumerate(s):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                return s[start:i + 1]
    return s


def _clean_json_text(raw: str) -> str:
    """Strip markdown fences, control chars, and return first balanced object."""
    c = raw.strip()
    if c.startswith("```"):
        c = re.sub(r"^```(?:json)?\s*|\s*```$", "", c, flags=re.IGNORECASE | re.DOTALL)
    c = _CONTROL_CHARS_RE.sub(" ", c)
    return _first_balanced_object(c)


# ---------------------------------------------------------------------------
# Text parsing helpers
# ---------------------------------------------------------------------------


def _strip_markdown(text: str) -> str:
    """Remove common markdown formatting that phi3.5 sometimes adds."""
    return _MARKDOWN_PREFIX_RE.sub("", text).replace("**", "").strip()


def _parse_summary(text: str) -> str:
    """Extract summary from plain-text LLM output. Strips any labels."""
    sm = re.search(r"(?:^|\n)\s*SUMMARY\s*:", text, re.IGNORECASE)
    if sm:
        return _strip_markdown(text[sm.end():].strip())
    return _strip_markdown(text.strip())


# ---------------------------------------------------------------------------
# Shared Ollama caller
# ---------------------------------------------------------------------------


def _call_ollama(system_prompt: str, user_msg: str, json_mode: bool = False) -> str:
    """
    Send a chat request to Ollama and return the raw response text.
    Acquires a Redis lock first so only one LLM call runs at a time
    across all spider subprocesses — phi3.5 produces garbled output
    when overwhelmed by concurrent requests.
    Raises OllamaUnavailableError if the model is unreachable.
    """
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
        "stream": False,
        "options": {"temperature": 0.0, "num_ctx": NUM_CTX},
    }
    if json_mode:
        payload["format"] = "json"

    body = json.dumps(payload).encode()

    req = urllib.request.Request(
        OLLAMA_URL + "/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    r = _get_redis()
    token = _acquire_llm_lock(r)
    try:
        # Check if we've hit the batch limit and need a VRAM reset
        call_count = int(r.get(_LLM_CALL_COUNTER_KEY) or 0)
        if call_count >= _LLM_BATCH_SIZE:
            _unload_model()
            r.set(_LLM_CALL_COUNTER_KEY, 0)

        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read())["message"]["content"].strip()
        # Brief cooldown between calls
        time.sleep(1)
        r.incr(_LLM_CALL_COUNTER_KEY)
        return result
    except Exception as e:
        raise OllamaUnavailableError(str(e)) from e
    finally:
        _release_llm_lock(r, token)


# ---------------------------------------------------------------------------
# Path-specific enrichment functions
# ---------------------------------------------------------------------------


def _enrich_structured(title: str, description: str, source: str) -> dict:
    """Path 1: Structured sources — summary + impact_points + remediation_steps via JSON."""
    msg = f"Title: {title}\nSource: {source}\nDescription: {description}"

    try:
        raw = _call_ollama(_PROMPT_STRUCTURED, msg, json_mode=True)
    except OllamaUnavailableError:
        raise

    result = dict(EMPTY_ENRICHMENT)
    try:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = json.loads(_clean_json_text(raw))

        result["summary"] = _strip_markdown(str(parsed.get("summary", "")).strip())

        raw_impacts = parsed.get("impact_points", [])
        if not isinstance(raw_impacts, list):
            raw_impacts = [raw_impacts]
        result["impact_points"] = [str(v).strip() for v in raw_impacts if str(v).strip()]

        raw_remediation = parsed.get("remediation_steps", [])
        if not isinstance(raw_remediation, list):
            raw_remediation = [raw_remediation]
        result["remediation_steps"] = [str(v).strip() for v in raw_remediation if str(v).strip()]

    except Exception as e:
        # Fallback: treat entire output as summary
        logger.warning(f"[Enrichment:Structured] JSON parse failed for '{title[:50]}': {e}")
        result["summary"] = _parse_summary(raw)

    return result


def _enrich_unstructured(title: str, description: str, source: str) -> dict:
    """
    Path 2: Unstructured sources — two sequential calls.
    Call 1 (extraction): JSON mode — products, OS, regions, impacts, remediation, mitigation.
    Call 2 (prose): plain text — summary only.
    """
    msg = f"Title: {title}\nSource: {source}\nDescription: {description}"
    result = dict(EMPTY_ENRICHMENT)

    # --- Call 1: Extraction (JSON mode) ---
    try:
        raw_extract = _call_ollama(_PROMPT_UNSTRUCTURED_EXTRACT, msg, json_mode=True)
    except OllamaUnavailableError:
        raise

    try:
        try:
            parsed = json.loads(raw_extract)
        except json.JSONDecodeError:
            parsed = json.loads(_clean_json_text(raw_extract))

        _EXTRACT_LIST_FIELDS = {
            "affected_os", "affected_regions", "impact_points",
            "remediation_steps", "temp_mitigation",
        }
        for key in _EXTRACT_LIST_FIELDS:
            val = parsed.get(key, [])
            if not isinstance(val, list):
                val = [val]
            result[key] = [str(v).strip() for v in val if str(v).strip()]

        raw_products = parsed.get("affected_products", [])
        if not isinstance(raw_products, list):
            raw_products = [raw_products]
        result["affected_products"] = normalize_affected_products(raw_products)

    except Exception as e:
        logger.warning(f"[Enrichment:Unstructured] Extraction parse failed for '{title[:50]}': {e}")

    # --- Call 2: Summary (plain text) ---
    try:
        raw_prose = _call_ollama(_PROMPT_UNSTRUCTURED_PROSE, msg, json_mode=False)
    except OllamaUnavailableError:
        raise

    result["summary"] = _parse_summary(raw_prose)
    return result


_VALID_SECTORS = {
    "banking & finance", "energy & utilities", "healthcare",
    "telecom", "government", "manufacturing", "retail",
    "education", "transportation", "technology",
}

# Canonical display names (title case)
_SECTOR_DISPLAY = {s: s.title() for s in _VALID_SECTORS}
_SECTOR_DISPLAY["banking & finance"] = "Banking & Finance"
_SECTOR_DISPLAY["energy & utilities"] = "Energy & Utilities"


def _parse_sectors(text: str) -> list[str]:
    """Extract SECTORS: line from LLM output and return validated sector list."""
    m = re.search(r"(?:^|\n)\s*SECTORS?\s*:\s*(.+)", text, re.IGNORECASE)
    if not m:
        return []
    raw = m.group(1).strip()
    if raw.lower() in ("none", "n/a", ""):
        return []
    sectors = []
    for part in raw.split(","):
        cleaned = part.strip().lower()
        if cleaned in _VALID_SECTORS:
            sectors.append(_SECTOR_DISPLAY[cleaned])
    return sectors


# ── Post-processing safety net: sector evidence keywords ──
# If the LLM assigns a sector but the article text contains none of these
# keywords, strip that sector. Catches hallucinated sector assignments.
_SECTOR_EVIDENCE = {
    "Banking & Finance": [
        "bank", "banking", "financial", "fintech", "payment", "insurance",
        "stock exchange", "credit card", "investment",
        "forex", "trading", "swift", "mortgage", "loan",
    ],
    "Healthcare": [
        "hospital", "health", "medical", "clinical", "patient", "pharma",
        "vaccine", "dicom", "hl7", "healthcare",
    ],
    "Manufacturing": [
        "factory", "manufacturing", "industrial", "automotive", "aerospace",
        "assembly line", "production line", "plant",
    ],
    "Education": [
        "university", "school", "campus", "student", "academic",
        "educational", "classroom", "curriculum",
    ],
    "Retail": [
        "retail", "e-commerce", "ecommerce", "merchant", "point of sale",
        "pos system", "shopif", "shopping",
    ],
}


def _verify_sectors(sectors: list[str], article_text: str) -> list[str]:
    """Strip sectors that have no keyword evidence in the article text."""
    if not sectors:
        return sectors
    text_lower = article_text.lower()
    verified = []
    for sector in sectors:
        evidence_words = _SECTOR_EVIDENCE.get(sector)
        if evidence_words is None:
            # No evidence check for this sector — keep it
            verified.append(sector)
        elif any(kw in text_lower for kw in evidence_words):
            verified.append(sector)
        else:
            logger.info(f"[Enrichment] Stripped hallucinated sector '{sector}' — no evidence in text")
    return verified


def _enrich_news(title: str, description: str, source: str) -> dict:
    """Path 3: News sources — summary + sectors + regions via JSON mode."""
    # LLM only needs the first 2000 chars to understand the story.
    # Full description is stored in DB untouched — this only limits what the LLM sees.
    llm_desc = description[:2000] if len(description) > 2000 else description
    msg = f"Title: {title}\nSource: {source}\nDescription: {llm_desc}"

    try:
        raw = _call_ollama(_PROMPT_NEWS, msg, json_mode=True)
    except OllamaUnavailableError:
        raise

    result = dict(EMPTY_ENRICHMENT)
    try:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = json.loads(_clean_json_text(raw))

        result["summary"] = _strip_markdown(str(parsed.get("summary", "")).strip())

        # Validate sectors against allowed list, then verify with keyword evidence
        raw_sectors = parsed.get("sectors", [])
        if not isinstance(raw_sectors, list):
            raw_sectors = [raw_sectors]
        sectors = []
        for s in raw_sectors:
            cleaned = str(s).strip().lower()
            if cleaned in _VALID_SECTORS:
                sectors.append(_SECTOR_DISPLAY[cleaned])
        result["sectors"] = _verify_sectors(sectors, f"{title} {description}")

        # Validate regions against allowed list
        _VALID_REGIONS = {
            "middle east", "mena", "europe", "north america",
            "asia-pacific", "africa", "latin america", "global",
        }
        raw_regions = parsed.get("regions", [])
        if not isinstance(raw_regions, list):
            raw_regions = [raw_regions]
        result["affected_regions"] = [
            str(r).strip() for r in raw_regions
            if str(r).strip().lower() in _VALID_REGIONS
        ]

    except Exception as e:
        logger.warning(f"[Enrichment:News] Parse failed for '{title[:50]}': {e}")

    return result


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

_PATH_TO_ENRICH = {
    "structured": _enrich_structured,
    "unstructured": _enrich_unstructured,
    "news": _enrich_news,
}


def enrich(title: str, description: str, source: str) -> dict:
    """
    Call phi3.5 via Ollama to extract structured fields from a security advisory.

    Routes to source-specific prompts based on source type.
    Returns a dict with all EMPTY_ENRICHMENT keys on any path.
    Raises OllamaUnavailableError if Ollama is unreachable.
    """
    path = _classify_source(source)
    enrich_fn = _PATH_TO_ENRICH[path]
    result = enrich_fn(title, description, source)
    logger.info(
        f"[Enrichment] phi3.5 OK for '{title[:50]}' ({path}) — "
        f"products={len(result.get('affected_products', []))}, "
        f"impacts={len(result.get('impact_points', []))}, "
        f"summary_len={len(result.get('summary', ''))}"
    )
    return result


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OllamaUnavailableError(Exception):
    """Raised when Ollama/phi3.5 cannot be reached."""
    pass


# ---------------------------------------------------------------------------
# Startup helper
# ---------------------------------------------------------------------------


def start_ollama() -> bool:
    """
    Try to start Ollama and load phi3.5.
    Sends a request to load the model — if Ollama is running but the model
    isn't loaded, this warms it up. If Ollama itself isn't running, this fails.
    """
    import time

    try:
        req = urllib.request.Request(OLLAMA_URL + "/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read()
    except Exception:
        logger.warning("[Enrichment] Ollama is not running — cannot auto-start from container")
        return False

    try:
        body = json.dumps({
            "model": MODEL,
            "messages": [{"role": "user", "content": "ping"}],
            "stream": False,
            "options": {"num_predict": 1, "num_ctx": NUM_CTX},
        }).encode()
        req = urllib.request.Request(
            OLLAMA_URL + "/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            r.read()
        logger.info("[Enrichment] Ollama phi3.5 started successfully")
        time.sleep(2)
        return True
    except Exception as e:
        logger.error(f"[Enrichment] Failed to start phi3.5: {e}")
        return False
