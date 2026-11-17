"""
NLP Classifier Service — TTPXHunter integration.

Uses the TTPXHunter model (SecureBERT fine-tuned) to:
1. Verify if text describes a real security threat
2. Extract MITRE ATT&CK TTP codes from threat descriptions
3. Detect exploit status from natural language
4. Extract affected product names

The model runs locally on GPU — no external API calls needed.
"""

import os
import re
import pickle
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# NLP server URL — loaded model served over HTTP to avoid per-subprocess loading
NLP_SERVER_URL = os.getenv("NLP_SERVER_URL", "http://127.0.0.1:5062")
_nlp_server_available = None  # None = not checked yet

# Lazy-loaded globals — fallback if NLP server is not running
_model = None
_tokenizer = None
_label_to_ttp = None  # Maps label index → TTP ID (e.g., 16 → "T1190")
_ttp_to_name = None   # Maps TTP ID → name (e.g., "T1190" → "Exploit Public-Facing Application")
_model_loaded = False
_model_failed = False

# Confidence threshold from the TTPXHunter paper
TTP_CONFIDENCE_THRESHOLD = 0.64

# Keywords that indicate active exploitation
EXPLOIT_KEYWORDS = [
    "actively exploited", "exploited in the wild", "exploitation in the wild",
    "being exploited", "under active exploitation", "zero-day",
    "0-day", "0day", "proof of concept", "poc available", "poc exploit",
    "exploit available", "exploit code", "exploit published",
    "weaponized", "actively attacked", "under attack",
]

# Common product/vendor names for extraction
PRODUCT_KEYWORDS = {
    "fortinet": "Fortinet", "fortigate": "Fortinet", "fortios": "Fortinet",
    "forticlient": "Fortinet", "fortimanager": "Fortinet",
    "cisco": "Cisco", "ios xe": "Cisco", "webex": "Cisco",
    "anyconnect": "Cisco",
    "microsoft": "Microsoft", "windows": "Microsoft Windows",
    "exchange": "Microsoft Exchange", "office 365": "Microsoft 365",
    "azure": "Microsoft Azure", "outlook": "Microsoft Outlook",
    "active directory": "Microsoft AD",
    "google": "Google", "chrome": "Google Chrome", "android": "Android",
    "chromium": "Chromium",
    "apache": "Apache", "tomcat": "Apache Tomcat", "struts": "Apache Struts",
    "log4j": "Apache Log4j", "httpd": "Apache HTTP Server",
    "linux": "Linux", "ubuntu": "Ubuntu", "debian": "Debian",
    "red hat": "Red Hat", "centos": "CentOS",
    "vmware": "VMware", "esxi": "VMware ESXi", "vcenter": "VMware vCenter",
    "palo alto": "Palo Alto", "pan-os": "Palo Alto PAN-OS",
    "sonicwall": "SonicWall",
    "juniper": "Juniper", "junos": "Juniper Junos",
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
    "nginx": "Nginx",
    "oracle": "Oracle", "java": "Java",
    "samsung": "Samsung", "apple": "Apple", "apple ios": "Apple iOS",
    "macos": "Apple macOS", "safari": "Apple Safari",
    "firefox": "Mozilla Firefox", "mozilla": "Mozilla",
    "openssl": "OpenSSL", "openssh": "OpenSSH",
    "qnap": "QNAP", "synology": "Synology",
    "zyxel": "ZyXEL", "tp-link": "TP-Link", "d-link": "D-Link",
    "hikvision": "Hikvision", "dahua": "Dahua",
    "sap": "SAP", "ibm": "IBM", "qradar": "IBM QRadar",
    "splunk": "Splunk", "elastic": "Elastic", "kibana": "Elastic Kibana",
    "gitlab": "GitLab", "github": "GitHub", "jenkins": "Jenkins",
    "docker": "Docker", "kubernetes": "Kubernetes",
    "aws": "AWS", "amazon": "AWS",
    "postgresql": "PostgreSQL", "mysql": "MySQL", "mongodb": "MongoDB",
    "redis": "Redis", "mariadb": "MariaDB",
    "telegram": "Telegram", "whatsapp": "WhatsApp", "signal": "Signal",
    "zoom": "Zoom", "teams": "Microsoft Teams", "slack": "Slack",
    "f5": "F5", "big-ip": "F5 BIG-IP",
    "ivanti": "Ivanti", "pulse secure": "Ivanti Pulse Secure",
    "citrix": "Citrix", "netscaler": "Citrix NetScaler",
    "sophos": "Sophos", "kaspersky": "Kaspersky",
    "crowdstrike": "CrowdStrike", "sentinelone": "SentinelOne",
    "mattermost": "Mattermost", "nextcloud": "Nextcloud",
    "roundcube": "Roundcube", "zimbra": "Zimbra",
}

# Paths for label mapping files
LABEL_DICT_PATH = "/app/label_dict.pkl"
TTP_ID_NAME_PATH = "/app/ttp_id_name.pkl"
LABEL_DICT_URL = "https://github.com/nanda-rani/TTPXHunter-Actionable-Threat-Intelligence-Extraction-as-TTPs-from-Finished-Cyber-Threat-Reports/raw/main/label_dict.pkl"
TTP_ID_NAME_URL = "https://github.com/nanda-rani/TTPXHunter-Actionable-Threat-Intelligence-Extraction-as-TTPs-from-Finished-Cyber-Threat-Reports/raw/main/ttp_id_name.pkl"


def _download_label_files():
    """Download label mapping files if not present."""
    import requests

    for path, url in [(LABEL_DICT_PATH, LABEL_DICT_URL), (TTP_ID_NAME_PATH, TTP_ID_NAME_URL)]:
        if not os.path.exists(path):
            logger.info(f"[NLP] Downloading {os.path.basename(path)}...")
            try:
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                with open(path, "wb") as f:
                    f.write(r.content)
                logger.info(f"[NLP] Downloaded {os.path.basename(path)}")
            except Exception as e:
                logger.error(f"[NLP] Failed to download {os.path.basename(path)}: {e}")


def _check_nlp_server():
    """Check if the NLP server is running and the model is loaded."""
    global _nlp_server_available
    import urllib.request
    import json as _json

    try:
        req = urllib.request.Request(f"{NLP_SERVER_URL}/health", method="GET")
        with urllib.request.urlopen(req, timeout=5) as r:
            data = _json.loads(r.read())
            _nlp_server_available = data.get("model_loaded", False)
    except Exception:
        _nlp_server_available = False

    return _nlp_server_available


def _classify_via_server(title, description):
    """Call the NLP server for classification instead of loading the model locally."""
    import urllib.request
    import json as _json

    body = _json.dumps({"title": title, "description": description}).encode()
    req = urllib.request.Request(
        f"{NLP_SERVER_URL}/classify",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return _json.loads(r.read())


def _load_model():
    """
    Lazy-load the TTPXHunter model.
    Prefers the NLP server if running — avoids 8-minute model load per subprocess.
    Falls back to local loading if the server is unavailable.
    """
    global _model, _tokenizer, _label_to_ttp, _ttp_to_name, _model_loaded, _model_failed
    import time as _time

    if _model_loaded or _model_failed:
        return _model_loaded

    # Check NLP server first — if it's up, we don't need to load locally
    if _check_nlp_server():
        logger.info("[NLP] NLP model ready (via NLP server — instant)")
        _model_loaded = True
        return True

    # NLP server might still be starting — wait up to 60s before falling back
    logger.info("[NLP] NLP server not ready yet — waiting for it to load...")
    for attempt in range(12):
        _time.sleep(5)
        if _check_nlp_server():
            logger.info("[NLP] NLP model ready (via NLP server — instant)")
            _model_loaded = True
            return True
        logger.info(f"[NLP] Waiting for NLP server... ({(attempt + 1) * 5}s)")

    # Fallback: load locally with progress logging
    try:
        logger.info("[NLP] NLP server unavailable — loading TTPXHunter locally...")
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch

        logger.info("[NLP] Loading tokenizer... (step 1/4)")
        _tokenizer = AutoTokenizer.from_pretrained("nanda-rani/TTPXHunter")

        logger.info("[NLP] Loading model weights... (step 2/4)")
        _model = AutoModelForSequenceClassification.from_pretrained("nanda-rani/TTPXHunter")

        # Move to GPU if available
        if torch.cuda.is_available():
            _model = _model.cuda()
            logger.info(f"[NLP] Model on GPU: {torch.cuda.get_device_name(0)} (step 3/4)")
        else:
            logger.info("[NLP] Model on CPU (step 3/4)")

        _model.eval()

        # Load label mappings
        logger.info("[NLP] Loading label mappings... (step 4/4)")
        _download_label_files()

        if os.path.exists(LABEL_DICT_PATH):
            with open(LABEL_DICT_PATH, "rb") as f:
                label_dict = pickle.load(f)
            _label_to_ttp = {int(v): k for k, v in label_dict.items()}

        if os.path.exists(TTP_ID_NAME_PATH):
            with open(TTP_ID_NAME_PATH, "rb") as f:
                _ttp_to_name = pickle.load(f)

        logger.info("[NLP] TTPXHunter model loaded locally — ready")
        _model_loaded = True
        return True

    except Exception as e:
        _model_failed = True
        logger.error(f"[NLP] Failed to load TTPXHunter: {e}")
        return False


def _get_ttp_info(label_index):
    """Convert a label index to TTP ID and name."""
    ttp_id = ""
    ttp_name = ""

    if _label_to_ttp and label_index in _label_to_ttp:
        ttp_id = _label_to_ttp[label_index]
        if _ttp_to_name and ttp_id in _ttp_to_name:
            ttp_name = _ttp_to_name[ttp_id]
        else:
            ttp_name = ttp_id

    return ttp_id, ttp_name

def _strip_markdown(text):
    """Strip markdown formatting before NLP processing."""
    if not text:
        return ""
    # Remove markdown headers
    text = re.sub(r'#{1,6}\s*', '', text)
    # Remove bold/italic markers
    text = re.sub(r'\*{1,3}([^*]+)\*{1,3}', r'\1', text)
    # Remove markdown links [text](url)
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Remove inline code backticks
    text = re.sub(r'`([^`]+)`', r'\1', text)
    # Remove code blocks
    text = re.sub(r'```[\s\S]*?```', '', text)
    # Remove horizontal rules
    text = re.sub(r'---+', '', text)
    # Remove bullet points
    text = re.sub(r'^\s*[-*+]\s+', '', text, flags=re.MULTILINE)
    # Remove numbered lists
    text = re.sub(r'^\s*\d+\.\s+', '', text, flags=re.MULTILINE)
    # Collapse multiple newlines
    text = re.sub(r'\n{2,}', '. ', text)
    # Collapse multiple spaces
    text = re.sub(r'\s{2,}', ' ', text)
    return text.strip()


def _split_sentences(text):
    """Split text into sentences for individual classification."""
    if not text:
        return []

    text = _strip_markdown(text)

    sentences = re.split(r'(?<=[.!?])\s+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) >= 10]

    return sentences


def extract_ttps(text):
    """
    Extract MITRE ATT&CK TTPs from text using TTPXHunter.

    Returns dict with:
        ttps: list of {"id": "T1190", "name": "Exploit Public-Facing Application", "confidence": 0.87}
        ttp_codes: comma-separated string of TTP IDs
        is_relevant: bool — True if any sentence had confidence >= threshold
        max_confidence: float — highest confidence score across all sentences
    """
    if not _load_model():
        return {
            "ttps": [],
            "ttp_codes": "",
            "is_relevant": True,
            "max_confidence": 0.0,
        }

    import torch

    sentences = _split_sentences(text)
    if not sentences:
        return {
            "ttps": [],
            "ttp_codes": "",
            "is_relevant": False,
            "max_confidence": 0.0,
        }

    ttps_found = []
    seen_ttp_ids = set()
    max_confidence = 0.0

    device = next(_model.parameters()).device

    for sentence in sentences:
        try:
            inputs = _tokenizer(
                sentence,
                return_tensors="pt",
                truncation=True,
                max_length=256,
                padding=True,
            )
            inputs = {k: v.to(device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = _model(**inputs)

            probs = torch.softmax(outputs.logits, dim=-1)
            top_prob = probs.max().item()
            predicted_class = probs.argmax().item()

            if top_prob > max_confidence:
                max_confidence = top_prob

            if top_prob >= TTP_CONFIDENCE_THRESHOLD:
                ttp_id, ttp_name = _get_ttp_info(predicted_class)

                if ttp_id and ttp_id not in seen_ttp_ids:
                    seen_ttp_ids.add(ttp_id)
                    ttps_found.append({
                        "id": ttp_id,
                        "name": ttp_name,
                        "confidence": round(top_prob, 4),
                    })

        except Exception as e:
            logger.debug(f"[NLP] Error classifying sentence: {e}")
            continue

    is_relevant = len(ttps_found) > 0 or max_confidence >= TTP_CONFIDENCE_THRESHOLD

    ttp_codes = ",".join(t["id"] for t in ttps_found)

    return {
        "ttps": ttps_found,
        "ttp_codes": ttp_codes,
        "is_relevant": is_relevant,
        "max_confidence": round(max_confidence, 4),
    }


def detect_exploit_status(text):
    """
    Detect if the text mentions active exploitation.

    Returns:
        "yes" — text explicitly mentions active exploitation
        "no" — text explicitly says not exploited
        "unknown" — no clear indication
    """
    if not text:
        return "unknown"

    text_lower = text.lower()

    for keyword in EXPLOIT_KEYWORDS:
        if keyword in text_lower:
            idx = text_lower.index(keyword)
            prefix = text_lower[max(0, idx - 20):idx]
            if "not " not in prefix and "no " not in prefix and "without " not in prefix:
                return "yes"

    no_exploit_keywords = [
        "not been exploited", "no known exploitation",
        "not exploited", "no exploitation observed",
        "not actively exploited",
    ]
    for keyword in no_exploit_keywords:
        if keyword in text_lower:
            return "no"

    return "unknown"


def extract_products(text):
    """
    Extract product/vendor names mentioned in the text.

    Returns:
        list of unique product names found
    """
    if not text:
        return []

    text_lower = text.lower()
    found_products = set()

    for keyword, product_name in PRODUCT_KEYWORDS.items():
        if keyword in text_lower:
            found_products.add(product_name)

    return sorted(found_products)


def classify_threat(title, description):
    """
    Full NLP classification of a threat item.

    Combines TTP extraction, exploit detection, and product extraction.
    Uses the NLP server if available, otherwise falls back to local model.

    Returns dict with:
        is_relevant: bool
        ttp_codes: str
        ttps: list
        exploit_status: str ("yes", "no", "unknown")
        products: list of str
        max_confidence: float
    """
    # Use NLP server if available — avoids 8-min model load per spider subprocess
    if _nlp_server_available:
        try:
            return _classify_via_server(title, description or "")
        except Exception as e:
            logger.warning(f"[NLP] Server call failed, falling back to local: {e}")

    full_text = f"{title}. {description}" if description else title

    ttp_result = extract_ttps(full_text)
    exploit_status = detect_exploit_status(full_text)
    products = extract_products(full_text)

    return {
        "is_relevant": ttp_result["is_relevant"],
        "ttp_codes": ttp_result["ttp_codes"],
        "ttps": ttp_result["ttps"],
        "exploit_status": exploit_status,
        "products": products,
        "max_confidence": ttp_result["max_confidence"],
    }