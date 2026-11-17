"""
Notifications API — Manage email notification recipients.

All endpoints are ADMIN-only to prevent unauthorized additions.
Recipients are organized by role (analyst, client) which determines
which alert tiers they receive.

Clients do NOT need a platform account — they are external recipients
who receive forwarded advisories only.
"""

import io
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import require_role
from app.database import get_db
from app.models.user import User, UserRole
from app.models.notification import NotificationRecipient, RecipientRole
from app.schemas.notification import (
    RecipientCreate,
    RecipientUpdate,
    RecipientResponse,
    RecipientListResponse,
    TestEmailRequest,
)

router = APIRouter()

# Maximum recipients to prevent bulk abuse (security mitigation)
MAX_RECIPIENTS = 200

# Maximum upload size — cap memory before parsing to prevent DoS / zip-bomb abuse.
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


async def _read_upload(file: UploadFile) -> bytes:
    """Read an uploaded file in bounded chunks, rejecting anything over the cap."""
    chunks, total = [], 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.get("/clients", response_model=list[RecipientResponse])
async def list_clients(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """List CLIENT recipients only — accessible to analysts for inventory management."""
    # Include both CLIENT and NOT_CONCERNED recipients (NOT_CONCERNED = opted out of emails
    # but still a client for inventory purposes). Exclude NOT_CONCERNED rows that belong
    # to platform users with a non-CLIENT role (e.g. analysts who opted out of emails).
    result = await db.execute(
        select(NotificationRecipient)
        .outerjoin(User, User.email == NotificationRecipient.email)
        .where(
            NotificationRecipient.role.in_([RecipientRole.CLIENT, RecipientRole.NOT_CONCERNED])
        )
        .where(
            or_(User.id.is_(None), User.role == UserRole.CLIENT)
        )
        .order_by(NotificationRecipient.full_name)
    )
    clients = result.scalars().all()
    return [RecipientResponse.model_validate(c) for c in clients]


@router.get("/recipients", response_model=RecipientListResponse)
async def list_recipients(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """List all notification recipients."""
    result = await db.execute(
        select(NotificationRecipient).order_by(NotificationRecipient.created_at.desc())
    )
    recipients = result.scalars().all()

    return RecipientListResponse(
        recipients=[RecipientResponse.model_validate(r) for r in recipients],
        total=len(recipients),
    )


@router.post("/recipients", response_model=RecipientResponse, status_code=201)
async def add_recipient(
    data: RecipientCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Add a new notification recipient. Clients do not need a platform account."""
    # Check recipient cap (prevents bulk abuse)
    count_result = await db.execute(select(func.count(NotificationRecipient.id)))
    total = count_result.scalar()
    if total >= MAX_RECIPIENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum recipients ({MAX_RECIPIENTS}) reached. Remove inactive recipients first.",
        )

    # Check for duplicate email
    existing = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.email == data.email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"Recipient with email '{data.email}' already exists.",
        )

    recipient = NotificationRecipient(
        email=data.email,
        # The company name is the client identity; fall back to it when no
        # optional contact-person name is supplied.
        full_name=(data.full_name or data.company),
        company=data.company,
        role=RecipientRole(data.role),
        interests=data.interests or [],
    )
    db.add(recipient)
    await db.flush()
    await db.refresh(recipient)

    from app.services.audit import log_action
    await log_action(
        db, current_user.email, current_user.role.value,
        "ADD_CLIENT", resource_type="client", resource_id=str(recipient.id),
        details=f"Added client '{recipient.full_name}' ({recipient.email})",
        event_metadata={"client_id": recipient.id, "email": recipient.email, "company": recipient.company},
    )

    # A new client can immediately match existing CVEs/threats — refresh badges.
    background_tasks.add_task(_refresh_client_matching_sync)

    return RecipientResponse.model_validate(recipient)


@router.put("/recipients/{recipient_id}", response_model=RecipientResponse)
async def update_recipient(
    recipient_id: int,
    data: RecipientUpdate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Update a notification recipient."""
    result = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.id == recipient_id)
    )
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    # Check for duplicate email if changing
    if data.email and data.email != recipient.email:
        existing = await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.email == data.email)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=409,
                detail=f"Email '{data.email}' is already assigned to another recipient.",
            )

    changed_fields = []
    if data.email is not None and data.email != recipient.email:
        changed_fields.append("email")
        recipient.email = data.email
    if data.full_name is not None and data.full_name != recipient.full_name:
        changed_fields.append("full_name")
        recipient.full_name = data.full_name
    if data.company is not None and data.company != recipient.company:
        changed_fields.append("company")
        recipient.company = data.company
    if data.role is not None:
        new_role = RecipientRole(data.role)
        if new_role != recipient.role:
            changed_fields.append("role")
        recipient.role = new_role
    if data.interests is not None and data.interests != recipient.interests:
        changed_fields.append("interests")
        recipient.interests = data.interests
    if data.is_active is not None and data.is_active != recipient.is_active:
        changed_fields.append("is_active")
        recipient.is_active = data.is_active

    await db.flush()
    await db.refresh(recipient)

    if changed_fields:
        from app.services.audit import log_action
        await log_action(
            db, current_user.email, current_user.role.value,
            "EDIT_CLIENT", resource_type="client", resource_id=str(recipient_id),
            details=f"Edited client '{recipient.full_name}': {', '.join(changed_fields)}",
            event_metadata={"client_id": recipient_id, "fields_changed": changed_fields},
        )

    # Role / active-state changes affect which clients match — refresh badges.
    if changed_fields:
        background_tasks.add_task(_refresh_client_matching_sync)

    return RecipientResponse.model_validate(recipient)


@router.delete("/recipients/{recipient_id}")
async def delete_recipient(
    recipient_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Delete a notification recipient."""
    result = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.id == recipient_id)
    )
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    from app.services.audit import log_action
    await log_action(
        db, current_user.email, current_user.role.value,
        "DELETE_CLIENT", resource_type="client", resource_id=str(recipient_id),
        details=f"Deleted client '{recipient.full_name}' ({recipient.email})",
        event_metadata={"client_id": recipient_id, "email": recipient.email, "company": recipient.company},
    )
    await db.delete(recipient)

    # Removing a client must clear its badges from every matched CVE/threat.
    background_tasks.add_task(_refresh_client_matching_sync)

    return {"message": f"Recipient '{recipient.email}' deleted successfully"}


@router.post("/recipients/import")
async def import_recipients_excel(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """
    Bulk import recipients from an Excel file (.xlsx).

    Expected columns (case-insensitive, order does not matter):
      email, full_name, company (optional), role, interests (optional, comma-separated)

    Rows with duplicate emails are skipped. Invalid rows are reported.
    """
    try:
        import openpyxl
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed on the server.")

    if not file.filename.endswith((".xlsx", ".xlsm")):
        raise HTTPException(status_code=400, detail="Only .xlsx files are supported.")

    contents = await _read_upload(file)

    try:
        wb = openpyxl.load_workbook(io.BytesIO(contents), read_only=True, data_only=True)
        ws = wb.active
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read Excel file. Ensure it is a valid .xlsx.")

    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        raise HTTPException(status_code=400, detail="Excel file is empty.")

    # Normalise header row
    header = [str(c).strip().lower().replace(" ", "_") if c else "" for c in rows[0]]

    def col(name):
        return header.index(name) if name in header else None

    idx_email = col("email")
    idx_name = col("full_name")
    idx_company = col("company")
    idx_role = col("role")
    idx_interests = col("interests")

    # Clients are companies: company is the required identity (person name optional).
    if idx_email is None or idx_company is None or idx_role is None:
        raise HTTPException(
            status_code=400,
            detail="Required columns missing. Need: email, company, role",
        )

    # Check current count
    count_result = await db.execute(select(func.count(NotificationRecipient.id)))
    current_total = count_result.scalar()

    imported = 0
    skipped = 0
    errors = []

    allowed_roles = {"analyst", "client", "not_concerned"}

    for row_num, row in enumerate(rows[1:], start=2):
        email = str(row[idx_email]).strip().lower() if row[idx_email] else ""
        full_name = str(row[idx_name]).strip() if row[idx_name] else ""
        company = str(row[idx_company]).strip() if idx_company is not None and row[idx_company] else None
        role_raw = str(row[idx_role]).strip().lower() if row[idx_role] else ""
        interests_raw = str(row[idx_interests]).strip() if idx_interests is not None and row[idx_interests] else ""

        if not email or not company or not role_raw:
            errors.append(f"Row {row_num}: missing required field (email/company/role) — skipped")
            skipped += 1
            continue
        # Company is the client identity; fall back to it for the display name.
        full_name = full_name or company

        if role_raw not in allowed_roles:
            errors.append(f"Row {row_num}: invalid role '{role_raw}' — skipped")
            skipped += 1
            continue

        if current_total + imported >= MAX_RECIPIENTS:
            errors.append(f"Row {row_num}: recipient cap ({MAX_RECIPIENTS}) reached — import stopped")
            break

        # Check duplicate
        existing = await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.email == email)
        )
        if existing.scalar_one_or_none():
            errors.append(f"Row {row_num}: '{email}' already exists — skipped")
            skipped += 1
            continue

        interests = [t.strip() for t in interests_raw.split(",") if t.strip()] if interests_raw else []

        recipient = NotificationRecipient(
            email=email,
            full_name=full_name,
            company=company,
            role=RecipientRole(role_raw),
            interests=interests,
        )
        db.add(recipient)
        imported += 1

    if imported:
        background_tasks.add_task(_refresh_client_matching_sync)

    return {
        "imported": imported,
        "skipped": skipped,
        "errors": errors[:20],  # cap error list to avoid huge responses
    }


@router.post("/recipients/import-preview")
async def import_preview(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Parse an Excel file and return a preview showing new clients, existing updates, and unchanged.
    Does NOT save — the analyst must confirm via import-confirm.
    """
    try:
        import openpyxl
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed on the server.")

    if not file.filename.endswith((".xlsx", ".xlsm")):
        raise HTTPException(status_code=400, detail="Only .xlsx files are supported.")

    contents = await _read_upload(file)
    try:
        wb = openpyxl.load_workbook(io.BytesIO(contents), read_only=True, data_only=True)
        ws = wb.active
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read Excel file.")

    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        raise HTTPException(status_code=400, detail="Excel file is empty.")

    header = [str(c).strip().lower().replace(" ", "_") if c else "" for c in rows[0]]

    def col(name):
        for alt in ([name] if isinstance(name, str) else name):
            if alt in header:
                return header.index(alt)
        return None

    idx_email = col("email")
    idx_name = col(["full_name", "name", "contact"])
    idx_company = col("company")
    idx_role = col("role")
    idx_interests = col("interests")

    # Clients are companies: company is the required identity (contact name optional).
    if idx_email is None or idx_company is None:
        raise HTTPException(status_code=400, detail="Required columns missing. Need: email, company")

    new_clients = []
    existing_updates = []
    unchanged = []
    errors = []

    for row_num, row in enumerate(rows[1:], start=2):
        email = str(row[idx_email]).strip().lower() if row[idx_email] else ""
        full_name = str(row[idx_name]).strip() if idx_name is not None and row[idx_name] else ""
        company = str(row[idx_company]).strip() if idx_company is not None and row[idx_company] else ""
        role_raw = str(row[idx_role]).strip().lower() if idx_role is not None and row[idx_role] else "client"
        interests_raw = str(row[idx_interests]).strip() if idx_interests is not None and row[idx_interests] else ""

        if not email or not company:
            errors.append({"row": row_num, "reason": "Missing email or company"})
            continue
        # Company is the client identity; fall back to it for the display name.
        full_name = full_name or company

        interests = [t.strip() for t in interests_raw.split(",") if t.strip()] if interests_raw else []

        # Check if exists
        result = await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.email == email)
        )
        existing = result.scalar_one_or_none()

        if existing:
            changes = {}
            if company and company != (existing.company or ""):
                changes["company"] = {"old": existing.company or "", "new": company}
            if role_raw != (existing.role.value if existing.role else ""):
                changes["role"] = {"old": existing.role.value if existing.role else "", "new": role_raw}
            if interests:
                old_interests = set(existing.interests or [])
                new_interests = set(interests)
                added = sorted(new_interests - old_interests)
                removed = sorted(old_interests - new_interests)
                if added or removed:
                    changes["interests"] = {"added": added, "removed": removed}

            if changes:
                existing_updates.append({
                    "id": existing.id,
                    "email": existing.email,
                    "full_name": existing.full_name,
                    "changes": changes,
                })
            else:
                unchanged.append({
                    "id": existing.id,
                    "email": existing.email,
                    "full_name": existing.full_name,
                })
        else:
            new_clients.append({
                "email": email,
                "full_name": full_name,
                "company": company,
                "role": role_raw,
                "interests": interests,
            })

    from app.services.audit import log_action
    await log_action(
        db, current_user.email, current_user.role.value,
        "IMPORT_CLIENTS_PREVIEW", resource_type="notification_recipients", resource_id="",
        details=f"Import preview: {len(new_clients)} new, {len(existing_updates)} updates, {len(unchanged)} unchanged",
        event_metadata={"new": len(new_clients), "updates": len(existing_updates), "unchanged": len(unchanged), "errors": len(errors)},
    )

    return {
        "new_clients": new_clients,
        "existing_updates": existing_updates,
        "unchanged": unchanged,
        "errors": errors[:20],
    }


class ImportConfirmRequest(BaseModel):
    new_clients: list[dict] = []
    apply_updates: list[dict] = []


@router.post("/recipients/import-confirm")
async def import_confirm(
    body: ImportConfirmRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Confirm import: create new clients and apply selected updates."""
    from app.services.audit import log_action

    created = 0
    updated = 0
    allowed_roles = {"analyst", "client", "not_concerned"}

    for client in body.new_clients:
        email = client.get("email", "").strip().lower()
        company = (client.get("company") or "").strip()
        # Company is the client identity; person name is optional.
        full_name = (client.get("full_name") or "").strip() or company
        if not email or not company:
            continue
        # Skip if already exists
        existing = await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.email == email)
        )
        if existing.scalar_one_or_none():
            continue
        role_raw = client.get("role", "client").lower()
        if role_raw not in allowed_roles:
            role_raw = "client"
        recipient = NotificationRecipient(
            email=email,
            full_name=full_name,
            company=company,
            role=RecipientRole(role_raw),
            interests=client.get("interests", []),
        )
        db.add(recipient)
        created += 1

    for upd in body.apply_updates:
        rid = upd.get("id")
        if not rid:
            continue
        result = await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.id == rid)
        )
        recipient = result.scalar_one_or_none()
        if not recipient:
            continue
        if "company" in upd and upd["company"]:
            recipient.company = upd["company"]
        if "role" in upd and upd["role"]:
            role_raw = upd["role"].lower()
            if role_raw in allowed_roles:
                recipient.role = RecipientRole(role_raw)
        if "interests" in upd and isinstance(upd["interests"], list):
            recipient.interests = upd["interests"]
        updated += 1

    await log_action(
        db, current_user.email, current_user.role.value,
        "IMPORT_CLIENTS_CONFIRM", resource_type="notification_recipients", resource_id="",
        details=f"Import confirmed: {created} created, {updated} updated",
        event_metadata={"created": created, "updated": updated},
    )

    if created or updated:
        background_tasks.add_task(_refresh_client_matching_sync)

    return {"created": created, "updated": updated}


@router.post("/recipients/{recipient_id}/preview-inventory")
async def preview_inventory(
    recipient_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Parse an inventory Excel file and compare against the client's existing inventory.
    Does NOT save — the analyst must confirm separately via PUT /inventory.
    """
    from app.services.inventory_parser import parse_inventory_excel

    if not file.filename.endswith((".xlsx", ".xlsm")):
        raise HTTPException(status_code=400, detail="Only .xlsx files are supported.")

    # Get recipient
    result = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.id == recipient_id)
    )
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    contents = await _read_upload(file)
    try:
        parsed = parse_inventory_excel(contents)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=400, detail="Could not parse Excel file. Ensure it is a valid .xlsx with Vendor/Product/Version columns.")

    # Compare against existing inventory
    existing = recipient.inventory or []
    existing_keys = {
        (e.get("vendor", "").lower(), e.get("product_family", "").lower(), e.get("version", "").lower())
        for e in existing
    }
    parsed_keys = {
        (p["vendor"].lower(), p["product_family"].lower(), p["version"].lower())
        for p in parsed
    }

    new_entries = [p for p in parsed if (p["vendor"].lower(), p["product_family"].lower(), p["version"].lower()) not in existing_keys]
    removed_entries = [e for e in existing if (e.get("vendor", "").lower(), e.get("product_family", "").lower(), e.get("version", "").lower()) not in parsed_keys]
    unchanged_count = len(parsed) - len(new_entries)

    # Detect unrecognized vendors
    from app.services.product_aliases import normalize_vendor
    unrecognized = []
    seen_raw = set()
    for p in parsed:
        raw = p["vendor_raw"]
        if raw not in seen_raw:
            seen_raw.add(raw)
            if normalize_vendor(raw) is None:
                unrecognized.append(raw)

    return {
        "parsed_count": len(parsed),
        "new_entries": new_entries[:50],  # cap to prevent huge responses
        "removed_entries": removed_entries[:50],
        "unchanged_count": unchanged_count,
        "unrecognized_vendors": unrecognized,
        "full_inventory": parsed,  # full parsed list for confirm step
    }


def _refresh_client_matching_sync():
    """
    Sync background task: runs AFTER any client/inventory mutation commits.

    Re-runs the matching engine against the live client inventory and writes
    fresh ``client_matches`` back to BOTH:
      1. the canonical ``cves`` / ``threats`` rows (what the analyst badge and
         CVE/Threat lists read from), and
      2. every unsent CVE/Threat enrichment proposal.

    Unlike the scraper's _run_client_matching, this writes the result even when
    it is empty, so that removing a product or a client clears stale badges
    instead of leaving them behind. This is what makes the "client matched"
    badge update live on every inventory edit, with no rescrape required.
    """
    import json
    import logging
    import psycopg2
    import psycopg2.extras
    from app.services.matching_engine import match_clients_for_cve
    from app.services.email_service import _get_sync_connection

    log = logging.getLogger(__name__)
    conn = None
    try:
        conn = _get_sync_connection()

        # ── 1. Canonical CVE rows (drive the analyst badge + CVE list) ──
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT cve_id, enrichment_data
                FROM cves
                WHERE enrichment_data IS NOT NULL
                  AND enrichment_data ? 'affected_products'
            """)
            cve_rows = cur.fetchall()

        for row in cve_rows:
            affected = (row["enrichment_data"] or {}).get("affected_products", [])
            matches = match_clients_for_cve(affected, conn) if affected else []
            with conn.cursor() as cur:
                # Merge just the client_matches key; write even when empty so
                # removals clear the badge.
                cur.execute(
                    """UPDATE cves
                       SET enrichment_data =
                           COALESCE(enrichment_data, '{}'::jsonb) || %s::jsonb
                       WHERE cve_id = %s""",
                    (json.dumps({"client_matches": matches}), row["cve_id"])
                )

        # ── 2. Canonical Threat rows ──
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, enrichment_data
                FROM threats
                WHERE enrichment_data IS NOT NULL
                  AND enrichment_data ? 'affected_products'
            """)
            threat_canon_rows = cur.fetchall()

        for row in threat_canon_rows:
            affected = (row["enrichment_data"] or {}).get("affected_products", [])
            matches = match_clients_for_cve(affected, conn) if affected else []
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE threats
                       SET enrichment_data =
                           COALESCE(enrichment_data, '{}'::jsonb) || %s::jsonb
                       WHERE id = %s""",
                    (json.dumps({"client_matches": matches}), row["id"])
                )

        # ── 3. CVE proposals not yet emailed ──
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT p.id, c.enrichment_data
                FROM cve_enrichment_proposals p
                JOIN cves c ON c.cve_id = p.cve_id
                WHERE p.client_email_sent_at IS NULL
                  AND c.enrichment_data IS NOT NULL
            """)
            cve_prop_rows = cur.fetchall()

        for row in cve_prop_rows:
            affected = (row["enrichment_data"] or {}).get("affected_products", [])
            matches = match_clients_for_cve(affected, conn) if affected else []
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE cve_enrichment_proposals SET client_matches = %s WHERE id = %s",
                    (json.dumps(matches), row["id"])
                )

        # ── 4. Threat proposals not yet emailed ──
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT p.id, t.enrichment_data
                FROM threat_enrichment_proposals p
                JOIN threats t ON t.id = p.threat_id
                WHERE p.client_email_sent_at IS NULL
                  AND t.enrichment_data IS NOT NULL
            """)
            threat_prop_rows = cur.fetchall()

        for row in threat_prop_rows:
            affected = (row["enrichment_data"] or {}).get("affected_products", [])
            matches = match_clients_for_cve(affected, conn) if affected else []
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE threat_enrichment_proposals SET client_matches = %s WHERE id = %s",
                    (json.dumps(matches), row["id"])
                )

        conn.commit()
        log.info(
            "[matching] client_matches refreshed: %d CVEs, %d threats, "
            "%d CVE proposals, %d threat proposals",
            len(cve_rows), len(threat_canon_rows),
            len(cve_prop_rows), len(threat_prop_rows),
        )

    except Exception as e:
        log.warning(f"[matching] client_matches refresh failed: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()


# Backwards-compatible alias (kept so existing call sites keep working).
_rematch_proposals_sync = _refresh_client_matching_sync


@router.put("/recipients/{recipient_id}/inventory")
async def confirm_inventory(
    recipient_id: int,
    body: dict,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Save the confirmed inventory to the client's profile.
    Body: {"inventory": [...]}
    """
    result = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.id == recipient_id)
    )
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    inventory = body.get("inventory", [])
    if not isinstance(inventory, list):
        raise HTTPException(status_code=400, detail="inventory must be a list")

    recipient.inventory = inventory
    # Extract unique vendor names
    vendor_set = set()
    for item in inventory:
        v = item.get("vendor", "")
        if v:
            vendor_set.add(v)
    recipient.vendors = sorted(vendor_set)

    await db.flush()
    await db.refresh(recipient)

    # Schedule re-match to run after this transaction commits so the sync
    # psycopg2 connection in the matching engine reads the committed inventory.
    background_tasks.add_task(_refresh_client_matching_sync)

    return RecipientResponse.model_validate(recipient)


@router.post("/recipients/import-inventory")
async def import_inventory_general(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    General inventory drop (not tied to a specific client).

    Parses an inventory sheet that carries a Company/Email header block above the
    Vendor/Product/Version table. The client is identified by EMAIL (the unique
    key). If a client with that email exists, the parsed inventory is merged into
    it. If none exists, a NEW client (role=client) is created — but only when the
    sheet provides a valid Company AND Email. Otherwise the request is rejected.
    """
    import re as _re
    from app.services.inventory_parser import parse_client_inventory_excel
    from app.services.audit import log_action

    if not file.filename.endswith((".xlsx", ".xlsm")):
        raise HTTPException(status_code=400, detail="Only .xlsx files are supported.")

    contents = await _read_upload(file)
    try:
        parsed = parse_client_inventory_excel(contents)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=400, detail="Could not parse the Excel file. Ensure it has a Vendor/Product/Version table.")

    entries = parsed.get("entries") or []
    company = (parsed.get("company") or "").strip()
    email = (parsed.get("email") or "").strip().lower()
    if not entries:
        raise HTTPException(status_code=400, detail="No Vendor/Product/Version rows found in the sheet.")

    # Identify the client by email (unique key).
    recipient = None
    if email:
        recipient = (await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.email == email)
        )).scalar_one_or_none()

    created = False
    if recipient is None:
        # Creating a new client requires a valid Company + Email in the sheet.
        if not company or not email or not _re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise HTTPException(
                status_code=422,
                detail="No matching client found. To create one, the sheet must include a 'Company:' and a valid 'Email:' header above the inventory table.",
            )
        total = (await db.execute(select(func.count(NotificationRecipient.id)))).scalar()
        if total >= MAX_RECIPIENTS:
            raise HTTPException(status_code=400, detail=f"Maximum recipients ({MAX_RECIPIENTS}) reached.")
        recipient = NotificationRecipient(
            email=email,
            full_name=company,   # clients are companies; company is the identity
            company=company,
            role=RecipientRole.CLIENT,
            interests=[],
        )
        db.add(recipient)
        await db.flush()
        created = True

    # Merge parsed inventory into the client's existing inventory (no wipe).
    def _key(e):
        return (str(e.get("vendor", "")).lower(),
                str(e.get("product_family", "")).lower(),
                str(e.get("version", "")).lower())

    merged = list(recipient.inventory or [])
    seen = {_key(e) for e in merged}
    added = 0
    for e in entries:
        if _key(e) not in seen:
            merged.append(e)
            seen.add(_key(e))
            added += 1
    recipient.inventory = merged
    recipient.vendors = sorted({i.get("vendor", "") for i in merged if i.get("vendor")})

    await db.flush()
    await db.refresh(recipient)

    await log_action(
        db, current_user.email, current_user.role.value,
        "IMPORT_INVENTORY_GENERAL", resource_type="client", resource_id=str(recipient.id),
        details=f"{'Created' if created else 'Updated'} client '{recipient.company}' via general inventory drop (+{added} products)",
        event_metadata={"created": created, "client_id": recipient.id, "products_added": added, "total_products": len(merged)},
    )

    background_tasks.add_task(_refresh_client_matching_sync)
    return {
        "created": created,
        "client": {"id": recipient.id, "company": recipient.company, "email": recipient.email},
        "products_added": added,
        "total_products": len(merged),
    }


ALLOWED_REGIONS = [
    "Middle East", "MENA", "Europe", "North America",
    "Asia-Pacific", "Africa", "Latin America", "Global",
]


@router.put("/recipients/{recipient_id}/regions")
async def update_regions(
    recipient_id: int,
    body: dict,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Save regions list to a client's profile. Body: {"regions": [...]}"""
    result = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.id == recipient_id)
    )
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    regions = body.get("regions", [])
    if not isinstance(regions, list):
        raise HTTPException(status_code=400, detail="regions must be a list")

    # Validate against allowed set
    invalid = [r for r in regions if r not in ALLOWED_REGIONS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid regions: {invalid}")

    recipient.regions = regions
    await db.flush()
    await db.refresh(recipient)

    # Keep badges consistent on any client-profile edit.
    background_tasks.add_task(_refresh_client_matching_sync)

    return RecipientResponse.model_validate(recipient)


@router.post("/test")
async def send_test_email(
    data: TestEmailRequest,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Send a test email to verify SMTP configuration works."""
    from app.services.email_service import send_email

    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #2E2E38; color: white; padding: 20px;">
            <h2 style="margin: 0; color: #38BDF8;">Cyber Threat Watch</h2>
            <p style="margin: 5px 0 0 0; color: #aaa;">Email Notification Test</p>
        </div>
        <div style="padding: 30px; background: #F6F6FA; border: 1px solid #DDDDE0;">
            <p>This is a test email from the Cyber Threat Watch notification system.</p>
            <p><strong>Message:</strong> {data.message}</p>
            <p><strong>Sent by:</strong> {current_user.email}</p>
            <p>If you received this, SMTP is configured correctly.</p>
        </div>
        <div style="padding: 15px; background: #2E2E38; color: #999; font-size: 11px; font-style: italic;">
            &copy; Cyber Threat Watch
        </div>
    </div>
    """

    success = send_email(
        to_emails=[data.recipient_email],
        subject="[Cyber Threat Watch] Test Email",
        html_body=html_body,
    )

    if success:
        return {"message": f"Test email sent to {data.recipient_email}"}
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to send test email. Check SMTP configuration and server logs.",
        )
