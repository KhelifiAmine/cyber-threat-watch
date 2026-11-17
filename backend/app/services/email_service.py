"""
Email Service — Handles rendering and sending vulnerability advisory emails.

Security mitigations implemented:
  1. SandboxedEnvironment with autoescape=True — prevents SSTI
  2. CRLF stripping on all email headers — prevents SMTP header injection
  3. Template loaded from file, never from_string()
  4. HTML escaping on all dynamic content — prevents email XSS

Tier routing:
  - URGENT (critical threats) → ANALYST + CLIENT (everyone needs to know)
  - HIGH / MEDIUM / LOW → ANALYST only (their job to monitor all threats)
  - ADMIN never receives alert emails (they build the platform, not monitor threats)

This service is used by Celery tasks (sync context), so it uses psycopg2 for
database access instead of async SQLAlchemy.
"""

import logging
import os
import re
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from typing import Optional

import psycopg2
import psycopg2.extras
from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import escape, Markup

from app.config import settings

logger = logging.getLogger(__name__)

# ─── Template Engine (secure configuration) ───
# Path: /app/app/services/email_service.py
# dirname x3: services/ → app/ → app/ → /app/
# Then join with templates/ → /app/templates/
_template_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "templates"
)
_jinja_env = SandboxedEnvironment(
    loader=FileSystemLoader(_template_dir),
    autoescape=True,
)


def _format_description(text):
    """
    Convert structured text (\\n\\n-separated paragraphs, '- ' bullet lines)
    into safe HTML with <p> and <ul><li> elements.

    Input is already autoescaped by Jinja2, but we escape again defensively
    since this filter returns Markup (safe HTML).
    """
    if not text:
        return Markup("")

    safe = str(escape(str(text)))
    lines = safe.split("\n")

    html_parts = []
    bullet_buffer = []

    def flush_bullets():
        if bullet_buffer:
            items = "".join(
                f'<li style="font-size:13px;color:#333;line-height:1.7;">{b}</li>'
                for b in bullet_buffer
            )
            html_parts.append(
                f'<ul style="margin:0 0 8px 0;padding-left:20px;">{items}</ul>'
            )
            bullet_buffer.clear()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("- "):
            bullet_buffer.append(stripped[2:])
        else:
            flush_bullets()
            html_parts.append(
                f'<p style="margin:0 0 8px 0;font-size:13px;color:#333;line-height:1.6;">{stripped}</p>'
            )

    flush_bullets()
    return Markup("\n".join(html_parts))


_jinja_env.filters["format_description"] = _format_description

# ─── Logo Path ───
_logo_path = os.path.join(_template_dir, "logo.png")


# ─── Security: CRLF Sanitization ───
def sanitize_header(value: str) -> str:
    """Strip \\r, \\n, \\t from email header values to prevent SMTP injection."""
    if not value:
        return ""
    return re.sub(r"[\r\n\t]", " ", str(value)).strip()


# ─── Advisory ID Generator ───
def generate_advisory_id(alert_id: int, created_at=None) -> str:
    """
    Generate an advisory ID in YYMMDD format matching the advisory template.
    Example: 260405 for April 5, 2026.
    """
    if created_at and hasattr(created_at, 'strftime'):
        return created_at.strftime("%y%m%d")
    return datetime.now(timezone.utc).strftime("%y%m%d")


# ─── Database Access (sync, for Celery tasks) ───
def _get_sync_connection():
    """Create a synchronous database connection for Celery task context."""
    sync_url = settings.SYNC_DATABASE_URL
    return psycopg2.connect(sync_url)


def get_alert_with_threat(alert_id: int) -> Optional[dict]:
    """Query alert and its linked threat data for email rendering."""
    conn = None
    try:
        conn = _get_sync_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    a.id as alert_id,
                    a.title as alert_title,
                    a.message as alert_message,
                    a.priority,
                    a.status,
                    a.trigger_rule,
                    a.email_sent,
                    a.created_at as alert_created_at,
                    COALESCE(t.id, c.id) as threat_id,
                    COALESCE(t.title, c.title, c.cve_id) as threat_title,
                    COALESCE(t.description, c.description) as threat_description,
                    COALESCE(t.source, c.source, 'Unknown') as source,
                    COALESCE(t.source_url, c.source_url) as source_url,
                    COALESCE(t.severity::text, c.cvss_severity) as severity,
                    COALESCE(t.threat_type, 'vulnerability') as threat_type,
                    COALESCE(t.ttp_codes, '') as ttp_codes,
                    t.risk_score as risk_score,
                    c.cvss_base_score as cvss_base_score,
                    c.cve_id as cve_identifier,
                    COALESCE(t.regions, 'Global') as regions,
                    COALESCE(t.published_at, c.published_at) as threat_published_at,
                    COALESCE(t.enrichment_data, c.enrichment_data) as enrichment_data
                FROM alerts a
                LEFT JOIN threats t ON a.threat_id = t.id
                LEFT JOIN cves c ON a.cve_id = c.id
                WHERE a.id = %s
            """, (alert_id,))
            return cur.fetchone()
    except Exception as e:
        logger.error(f"[Email] Failed to query alert {alert_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def get_recipients_for_priority(priority: str) -> list[str]:
    """
    Query active recipients for automatic alerts.

    Only analysts receive automatic emails — regardless of priority. Clients
    never receive anything automatically; they only receive what an analyst
    (via the review workflow) chooses to forward.
    """
    conn = None
    try:
        conn = _get_sync_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT email FROM notification_recipients WHERE is_active = true AND role = 'ANALYST'"
            )
            rows = cur.fetchall()
            return [row["email"] for row in rows]
    except Exception as e:
        logger.error(f"[Email] Failed to query recipients: {e}")
        return []
    finally:
        if conn:
            conn.close()



def get_client_recipients() -> list[str]:
    """Active CLIENT recipients for manually-forwarded advisories."""
    conn = None
    try:
        conn = _get_sync_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT email FROM notification_recipients WHERE is_active = true AND role = 'CLIENT'"
            )
            return [row["email"] for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"[Email] Failed to query client recipients: {e}")
        return []
    finally:
        if conn:
            conn.close()


def get_forward_recipients(recipient_ids: list[int] = None) -> list[dict]:
    """
    Recipients for analyst-forwarded advisories.

    If recipient_ids is provided, filter to only those IDs.
    Otherwise return all active non-analyst recipients (CLIENT + NOT_CONCERNED).
    NOT_CONCERNED blocks auto-alerts but NOT analyst-forwarded advisories.
    """
    conn = None
    try:
        conn = _get_sync_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if recipient_ids:
                cur.execute(
                    "SELECT id, email, full_name FROM notification_recipients "
                    "WHERE is_active = true AND role != 'ANALYST' AND id = ANY(%s)",
                    (recipient_ids,)
                )
            else:
                cur.execute(
                    "SELECT id, email, full_name FROM notification_recipients "
                    "WHERE is_active = true AND role != 'ANALYST'"
                )
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"[Email] Failed to query forward recipients: {e}")
        return []
    finally:
        if conn:
            conn.close()


def get_all_client_recipients_for_ui() -> list[dict]:
    """
    All active non-analyst recipients for the send-to-clients UI.
    Returns id, email, full_name, company, role, interests for the frontend selection list.
    """
    conn = None
    try:
        conn = _get_sync_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, email, full_name, company, role, interests FROM notification_recipients "
                "WHERE is_active = true AND role != 'ANALYST' ORDER BY full_name"
            )
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"[Email] Failed to query client recipients for UI: {e}")
        return []
    finally:
        if conn:
            conn.close()


def mark_alert_email_sent(alert_id: int):
    """Update alert to mark email as sent."""
    conn = None
    try:
        conn = _get_sync_connection()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET email_sent = true WHERE id = %s",
                (alert_id,)
            )
        conn.commit()
    except Exception as e:
        logger.error(f"[Email] Failed to mark alert {alert_id} as sent: {e}")
    finally:
        if conn:
            conn.close()


# ─── CVE Extraction ───
def extract_cve_ids(text: str) -> str:
    """Extract CVE IDs from text for display in advisory."""
    if not text:
        return ""
    cves = list(set(re.findall(r"CVE-\d{4}-\d{4,}", str(text))))
    return ", ".join(sorted(cves)) if cves else ""


# ─── Enrichment Data → Template Format ───
def _build_enrichment_vars(enrichment_data) -> dict:
    """
    Convert enrichment flat-list output to the format the email template expects.
    enrichment_data may be a dict (from DB JSONB) or None.
    """
    ed = enrichment_data if isinstance(enrichment_data, dict) else {}

    # affected_products is now a list of {name, versions, notes} dicts
    # straight from the enrichment model. affected_os is still a flat list of
    # strings, which we merge into the products table as name-only rows.
    product_entries = []
    for p in ed.get("affected_products", []):
        if isinstance(p, dict):
            name = str(p.get("name", "")).strip()
            if name:
                product_entries.append({
                    "name": name,
                    "versions": str(p.get("versions", "")).strip(),
                    "notes": str(p.get("notes", "")).strip(),
                })
        elif p:
            product_entries.append({"name": str(p).strip(), "versions": "", "notes": ""})

    for os_name in ed.get("affected_os", []):
        if os_name:
            product_entries.append({"name": str(os_name).strip(), "versions": "", "notes": ""})

    affected_products = product_entries

    # impact_points: list of strings — pass directly
    impact_points = [p for p in ed.get("impact_points", []) if p]

    # remediation_steps: ["do X"] -> [{"label": "1", "action": "do X", ...}]
    remediation_steps = [
        {"label": str(i + 1), "action": step, "reference_label": "", "reference_url": ""}
        for i, step in enumerate(ed.get("remediation_steps", []))
        if step
    ]

    # temp_mitigation: list of strings — pass as temp_mitigation_points
    temp_mitigation_points = [p for p in ed.get("temp_mitigation", []) if p]

    # Summary and conclusion from LLM
    summary = str(ed.get("summary", "")).strip()
    conclusion = str(ed.get("conclusion", "")).strip()

    # Regions
    regions = [r for r in ed.get("affected_regions", []) if r]

    return {
        "affected_products": affected_products,
        "impact_points": impact_points,
        "remediation_steps": remediation_steps,
        "temp_mitigation_points": temp_mitigation_points,
        "summary": summary,
        "conclusion": conclusion,
        "regions": regions,
    }


# ─── Template Rendering ───
def render_alert_email(alert_data: dict) -> str:
    """Render the vulnerability advisory email template."""
    template = _jinja_env.get_template("alert_email.html")

    created_at = alert_data.get("alert_created_at", datetime.now(timezone.utc))

    # Extract CVE IDs from threat description, ttp_codes, alert title/message,
    # plus the direct CVE identifier when the alert is CVE-based.
    cve_sources = " ".join(filter(None, [
        str(alert_data.get("cve_identifier", "")),
        str(alert_data.get("alert_title", "")),
        str(alert_data.get("threat_description", "")),
        str(alert_data.get("ttp_codes", "")),
        str(alert_data.get("alert_message", "")),
    ]))
    cve_ids = extract_cve_ids(cve_sources)

    # Resolve risk_score: threat rows have it directly; CVE-only alerts do not,
    # so fall back to parsing "Risk score: N" from the alert message.
    risk_score = alert_data.get("risk_score")
    if risk_score is None:
        msg = str(alert_data.get("alert_message", ""))
        m = re.search(r"Risk score:\s*([0-9]+(?:\.[0-9]+)?)", msg)
        if m:
            try:
                risk_score = float(m.group(1))
            except ValueError:
                risk_score = 0
    if risk_score is None:
        risk_score = 0

    # Format dates for display
    published_display = ""
    published_at = alert_data.get("threat_published_at")
    if published_at and hasattr(published_at, 'strftime'):
        published_display = published_at.strftime("%d %B %Y")

    created_display = ""
    if created_at and hasattr(created_at, 'strftime'):
        created_display = created_at.strftime("%d %B %Y")

    # Build template vars from enrichment_data stored in the threats row
    enrichment_vars = _build_enrichment_vars(alert_data.get("enrichment_data"))

    # Auto-populate additional resources from the threat's source URL
    source_url = alert_data.get("source_url", "") or ""
    source_name = alert_data.get("source", "") or "Source Advisory"
    additional_resources = [{"name": source_name, "url": source_url}] if source_url else []

    return template.render(
        advisory_id=generate_advisory_id(
            alert_data.get("alert_id", 0), created_at
        ),
        alert_title=alert_data.get("alert_title", ""),
        alert_message=alert_data.get("alert_message", ""),
        threat_description=alert_data.get("threat_description", ""),
        severity=str(alert_data.get("severity", "")).upper(),
        risk_score=risk_score,
        cvss_score=alert_data.get("cvss_base_score"),
        cve_ids=cve_ids,
        published_at=published_display,
        alert_created_at=created_display,
        affected_products=enrichment_vars["affected_products"],
        impact_points=enrichment_vars["impact_points"],
        remediation_steps=enrichment_vars["remediation_steps"],
        temp_mitigation_points=enrichment_vars["temp_mitigation_points"],
        enrichment_summary=enrichment_vars["summary"],
        enrichment_conclusion=enrichment_vars["conclusion"],
        regions=enrichment_vars["regions"],
        additional_resources=additional_resources,
        year=datetime.now(timezone.utc).year,
    )



# ─── SMTP Sending ───
def send_email(to_emails: list[str], subject: str, html_body: str, cc_emails: list[str] = None) -> bool:
    """
    Send an HTML email with the Logo embedded as an inline image.
    All header values are sanitized against CRLF injection.
    """
    if not settings.SMTP_ENABLED:
        logger.info("[Email] SMTP disabled, skipping send")
        return False

    if not to_emails:
        logger.warning("[Email] No recipients, skipping send")
        return False

    safe_subject = sanitize_header(subject)
    safe_from_name = sanitize_header(settings.SMTP_FROM_NAME)
    safe_from_email = sanitize_header(settings.SMTP_FROM_EMAIL)

    try:
        # Build multipart message with related content (for inline images)
        msg = MIMEMultipart("related")
        msg["Subject"] = safe_subject
        msg["From"] = f"{safe_from_name} <{safe_from_email}>"
        msg["To"] = sanitize_header(to_emails[0])
        if len(to_emails) > 1:
            msg["Bcc"] = ", ".join(sanitize_header(e) for e in to_emails[1:])
        if cc_emails:
            msg["Cc"] = ", ".join(sanitize_header(e) for e in cc_emails)

        # Attach the HTML body
        html_part = MIMEMultipart("alternative")
        html_part.attach(MIMEText(html_body, "html", "utf-8"))
        msg.attach(html_part)

        # Attach the Logo as inline image (referenced by cid:logo in templates)
        if os.path.exists(_logo_path):
            with open(_logo_path, "rb") as f:
                logo_data = f.read()
            logo_image = MIMEImage(logo_data, _subtype="png")
            logo_image.add_header("Content-ID", "<logo>")
            logo_image.add_header("Content-Disposition", "inline", filename="logo.png")
            msg.attach(logo_image)
        else:
            logger.warning(f"[Email] Logo not found at {_logo_path}")

        # Connect to SMTP server
        if settings.SMTP_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30)
            server.starttls()
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30)

        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

        server.send_message(msg)
        server.quit()

        logger.info(f"[Email] Sent '{safe_subject}' to {len(to_emails)} recipients")
        return True

    except smtplib.SMTPException as e:
        logger.error(f"[Email] SMTP error: {e}")
        return False
    except ConnectionRefusedError:
        logger.error(f"[Email] Cannot connect to {settings.SMTP_HOST}:{settings.SMTP_PORT}")
        return False
    except Exception as e:
        logger.error(f"[Email] Unexpected error: {e}")
        return False


def send_news_email(
    to_emails: list[str],
    news_id: str,
    title: str,
    summary: str,
    description: str,
    sectors: list[str],
    source: str,
    published_date: str,
    enrichment_data: dict = None,
) -> bool:
    """Render and send a news advisory email using the news_email.html template."""
    from datetime import datetime

    ed = enrichment_data if isinstance(enrichment_data, dict) else {}

    # Use LLM summary/conclusion from enrichment if available
    display_summary = ed.get("summary", "") or summary
    conclusion = ed.get("conclusion", "")
    regions = [r for r in ed.get("affected_regions", []) if r]

    # Affected products from enrichment
    affected_products = []
    for p in ed.get("affected_products", []):
        if isinstance(p, dict) and p.get("name"):
            affected_products.append(p)

    # Impact and remediation
    impact_points = [p for p in ed.get("impact_points", []) if p]
    remediation_steps = [s for s in ed.get("remediation_steps", []) if s]

    template = _jinja_env.get_template("news_email.html")
    html = template.render(
        news_id=news_id,
        title=title,
        summary=display_summary,
        description=description,
        conclusion=conclusion,
        regions=regions,
        affected_products=affected_products,
        impact_points=impact_points,
        remediation_steps=remediation_steps,
        sectors=sectors,
        source=source,
        published_date=published_date,
        year=datetime.utcnow().year,
    )
    subject = f"Cyber News — {title[:80]}"
    return send_email(to_emails, subject, html)