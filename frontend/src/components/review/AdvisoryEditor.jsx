/**
 * AdvisoryEditor — Full-screen advisory composer with live email preview.
 *
 * Accepts a normalized `advisory` object and four callbacks:
 *   onSave(form)              — persist edits to the DB (PATCH CVE/Threat)
 *   onApprove(form)           — mark proposal APPROVED (removes from queue)
 *   onClose(form)             — mark proposal REJECTED  (removes from queue)
 *   onSend(form, recipientIds)— save then send the advisory email
 *   onDone()                  — close the editor and refresh the queue
 *
 * The `advisory` shape is produced by `proposalToAdvisory()` in ReviewPage.
 * It contains both source metadata (proposalId, kind, cveId/threatId) and
 * all editable content fields.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import api from "../../api/axios";
import { useToast } from "../../context/ToastContext";
import { errorMessage } from "../../api/errors";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SECTOR_OPTIONS = [
  "Banking & Finance", "Energy & Utilities", "Healthcare", "Telecom",
  "Government", "Manufacturing", "Retail", "Education", "Transportation", "Technology",
];

function buildPreviewPayload(form) {
  return {
    kind: form.kind,
    advisory_id: form.advisoryId || null,
    title: form.title || "",
    summary: form.summary || "",
    description: form.description || "",
    cve_ids: form.cveIds || "",
    cvss_score: form.kind === "cve" ? (form.cvssScore ?? null) : null,
    risk_score: form.kind === "threat" ? (form.riskScore ?? null) : null,
    severity:
      form.kind === "cve"
        ? (form.cvssSeverity || "")
        : (form.severity || ""),
    published_at: form.publishedAt || null,
    affected_products: (form.enrichedProducts || [])
      .filter((p) => p.name && p.name.trim())
      .map((p) => ({ name: p.name || "", versions: p.versions || "", notes: p.notes || "" })),
    impact_points: (form.impactPoints || []).filter(Boolean),
    remediation_steps: (form.remediationSteps || [])
      .filter((s) => s.action && s.action.trim())
      .map((s) => ({
        label: s.label || "",
        action: s.action || "",
        reference_label: s.reference_label || "",
        reference_url: s.reference_url || "",
      })),
    temp_mitigation_points: (form.tempMitigation || []).filter(Boolean),
    additional_resources: (form.additionalResources || [])
      .filter((r) => r.url && r.url.trim())
      .map((r) => ({ name: r.name || "", url: r.url || "" })),
    sectors: form.sectors || [],
    source: form.source || "",
    enrichment_summary: form.enrichmentSummary || "",
    enrichment_conclusion: form.enrichmentConclusion || "",
    conclusion: form.enrichmentConclusion || "",
    regions: form.enrichmentRegions || [],
  };
}

// ─── Sub-editors ──────────────────────────────────────────────────────────────

function FieldLabel({ children, required }) {
  return (
    <span className="block text-[10px] font-semibold uppercase tracking-widest text-gray-500 mb-1">
      {children}
      {required && <span className="text-red-400 ml-0.5">*</span>}
    </span>
  );
}

function SectionHeading({ children }) {
  return (
    <div className="flex items-center gap-2 pt-2">
      <span className="text-xs font-semibold text-gray-300 uppercase tracking-wide">
        {children}
      </span>
      <div className="flex-1 h-px bg-[#2a2a4a]" />
    </div>
  );
}

const inputCls =
  "w-full bg-[#0f0f1f] border border-[#2a2a4a] rounded px-3 py-1.5 text-sm text-gray-200 outline-none focus:border-[#38BDF8]/40 placeholder-gray-700 transition-colors";

const textareaCls =
  "w-full bg-[#0f0f1f] border border-[#2a2a4a] rounded px-3 py-2 text-sm text-gray-200 outline-none focus:border-[#38BDF8]/40 placeholder-gray-700 transition-colors resize-none";

const selectCls =
  "w-full bg-[#0f0f1f] border border-[#2a2a4a] rounded px-3 py-1.5 text-sm text-gray-200 outline-none focus:border-[#38BDF8]/40 transition-colors";

const btnSmCls =
  "text-xs text-gray-400 hover:text-gray-200 px-2 py-0.5 rounded border border-[#2a2a4a] hover:border-[#3a3a5a] hover:bg-[#1a1a2e] transition-colors";


function BulletsEditor({ label, value = [], onChange, placeholder = "Add item…" }) {
  const [draft, setDraft] = useState("");

  const add = () => {
    const trimmed = draft.trim();
    if (!trimmed) return;
    onChange([...value, trimmed]);
    setDraft("");
  };

  const remove = (idx) => onChange(value.filter((_, i) => i !== idx));
  const edit = (idx, text) => onChange(value.map((v, i) => (i === idx ? text : v)));

  return (
    <div className="space-y-2">
      <SectionHeading>{label}</SectionHeading>
      <ul className="space-y-1">
        {value.map((item, idx) => (
          <li key={idx} className="flex items-center gap-2">
            <span className="text-[#38BDF8] text-xs shrink-0">•</span>
            <input
              className="flex-1 bg-transparent border-b border-[#2a2a4a] text-sm text-gray-200 outline-none py-0.5 focus:border-[#38BDF8]/40"
              value={item}
              onChange={(e) => edit(idx, e.target.value)}
            />
            <button
              onClick={() => remove(idx)}
              className="text-gray-700 hover:text-red-400 text-base leading-none transition-colors"
            >
              ×
            </button>
          </li>
        ))}
      </ul>
      <div className="flex gap-2">
        <input
          className={inputCls}
          placeholder={placeholder}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), add())}
        />
        <button onClick={add} className={btnSmCls}>
          Add
        </button>
      </div>
    </div>
  );
}


function ProductsEditor({ value = [], onChange }) {
  const addRow = () =>
    onChange([...value, { name: "", versions: "", notes: "" }]);
  const removeRow = (idx) => onChange(value.filter((_, i) => i !== idx));
  const editRow = (idx, field, text) =>
    onChange(value.map((row, i) => (i === idx ? { ...row, [field]: text } : row)));

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 pt-2">
        <span className="text-xs font-semibold text-gray-300 uppercase tracking-wide">
          Affected Products
        </span>
        <div className="flex-1 h-px bg-[#2a2a4a]" />
        <button onClick={addRow} className={btnSmCls}>
          + Add
        </button>
      </div>
      {value.length === 0 && (
        <p className="text-xs text-gray-600 italic">
          No affected products listed. Adding at least one improves client matching accuracy.
        </p>
      )}
      {value.length > 0 && (
        <div className="space-y-1">
          <div className="grid grid-cols-[1fr_1fr_1fr_20px] gap-2 text-[10px] text-gray-600 uppercase tracking-wide px-1">
            <span>Product / OS</span>
            <span>Affected Versions</span>
            <span>Notes</span>
            <span />
          </div>
          {value.map((row, idx) => (
            <div key={idx} className="grid grid-cols-[1fr_1fr_1fr_20px] gap-2 items-center">
              <input
                className={inputCls}
                placeholder="e.g. IBM QRadar"
                value={row.name}
                onChange={(e) => editRow(idx, "name", e.target.value)}
              />
              <input
                className={`${inputCls} ${!row.name?.trim() ? "opacity-40 cursor-not-allowed" : ""}`}
                placeholder="e.g. 7.5.0 – UP14"
                value={row.versions}
                disabled={!row.name?.trim()}
                onChange={(e) => editRow(idx, "versions", e.target.value)}
              />
              <input
                className={inputCls}
                placeholder="Optional note"
                value={row.notes}
                onChange={(e) => editRow(idx, "notes", e.target.value)}
              />
              <button
                onClick={() => removeRow(idx)}
                className="text-gray-700 hover:text-red-400 text-base leading-none transition-colors"
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


function RemediationEditor({ value = [], onChange }) {
  const addStep = () =>
    onChange([
      ...value,
      { label: String(value.length + 1), action: "", reference_label: "", reference_url: "" },
    ]);

  const removeStep = (idx) => {
    const updated = value
      .filter((_, i) => i !== idx)
      .map((s, i) => ({ ...s, label: String(i + 1) }));
    onChange(updated);
  };

  const editStep = (idx, field, text) =>
    onChange(value.map((s, i) => (i === idx ? { ...s, [field]: text } : s)));

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 pt-2">
        <span className="text-xs font-semibold text-gray-300 uppercase tracking-wide">
          Remediation Steps
        </span>
        <div className="flex-1 h-px bg-[#2a2a4a]" />
        <button onClick={addStep} className={btnSmCls}>
          + Add Step
        </button>
      </div>
      {value.length === 0 && (
        <p className="text-xs text-gray-700 italic">No remediation steps. Click + Add Step.</p>
      )}
      <div className="space-y-2">
        {value.map((step, idx) => (
          <div
            key={idx}
            className="flex gap-3 items-start bg-[#0f0f1f] border border-[#2a2a4a] rounded p-3"
          >
            <span className="text-[#38BDF8] font-bold text-sm w-5 shrink-0 mt-1">
              {step.label}
            </span>
            <div className="flex-1 space-y-1.5">
              <textarea
                rows={2}
                className={textareaCls}
                placeholder="What to do…"
                value={step.action}
                onChange={(e) => editStep(idx, "action", e.target.value)}
              />
              <div className="grid grid-cols-2 gap-1">
                <input
                  className={inputCls}
                  placeholder="Reference label (optional)"
                  value={step.reference_label}
                  onChange={(e) => editStep(idx, "reference_label", e.target.value)}
                />
                <input
                  className={inputCls}
                  placeholder="Reference URL (optional)"
                  value={step.reference_url}
                  onChange={(e) => editStep(idx, "reference_url", e.target.value)}
                />
              </div>
            </div>
            <button
              onClick={() => removeStep(idx)}
              className="text-gray-700 hover:text-red-400 text-base leading-none mt-1 transition-colors"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}


function ResourcesEditor({ value = [], onChange }) {
  const addResource = () => onChange([...value, { name: "", url: "" }]);
  const removeResource = (idx) => onChange(value.filter((_, i) => i !== idx));
  const editResource = (idx, field, text) =>
    onChange(value.map((r, i) => (i === idx ? { ...r, [field]: text } : r)));

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 pt-2">
        <span className="text-xs font-semibold text-gray-300 uppercase tracking-wide">
          Additional Resources
        </span>
        <div className="flex-1 h-px bg-[#2a2a4a]" />
        <button onClick={addResource} className={btnSmCls}>
          + Add Link
        </button>
      </div>
      {value.length === 0 && (
        <p className="text-xs text-gray-700 italic">No resources added.</p>
      )}
      <div className="space-y-1">
        {value.map((r, idx) => (
          <div key={idx} className="flex gap-2 items-center">
            <input
              className={`${inputCls} w-36`}
              placeholder="Label"
              value={r.name}
              onChange={(e) => editResource(idx, "name", e.target.value)}
            />
            <input
              className={`${inputCls} flex-1`}
              placeholder="https://…"
              value={r.url}
              onChange={(e) => editResource(idx, "url", e.target.value)}
            />
            <button
              onClick={() => removeResource(idx)}
              className="text-gray-700 hover:text-red-400 text-base leading-none transition-colors"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}


// ─── Send Modal ───────────────────────────────────────────────────────────────

function SendModal({ clients, selectedIds, onToggle, onSend, onClose, sending, clientMatches = [] }) {
  // Build a map of client_id → match info
  const matchMap = {};
  for (const m of clientMatches) {
    matchMap[m.client_id] = m;
  }

  // Sort clients: high matches first, partial second, then the rest
  const sorted = [...clients].sort((a, b) => {
    const ma = matchMap[a.id];
    const mb = matchMap[b.id];
    const scoreA = ma ? (ma.confidence === "high" ? 0 : 1) : 2;
    const scoreB = mb ? (mb.confidence === "high" ? 0 : 1) : 2;
    return scoreA - scoreB;
  });

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/70">
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg w-[480px] p-6 space-y-4 shadow-2xl">
        <h3 className="text-white font-semibold text-sm">Send Advisory</h3>
        <p className="text-xs text-gray-500">
          Select specific recipients, or leave all unchecked to send to all active clients.
          {clientMatches.length > 0 && (
            <span className="text-[#38BDF8] ml-1">
              {clientMatches.length} client{clientMatches.length !== 1 ? "s" : ""} matched by inventory.
            </span>
          )}
        </p>
        <div className="space-y-1 max-h-64 overflow-y-auto pr-1">
          {sorted.length === 0 && (
            <p className="text-xs text-gray-600 italic">No clients found.</p>
          )}
          {sorted.map((c) => {
            const match = matchMap[c.id];
            return (
              <label
                key={c.id}
                className="flex items-start gap-3 cursor-pointer py-1.5 px-2 rounded hover:bg-[#1a1a2e] transition-colors"
              >
                <input
                  type="checkbox"
                  checked={selectedIds.includes(c.id)}
                  onChange={() => onToggle(c.id)}
                  className="accent-[#38BDF8] mt-0.5 shrink-0"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2">
                    <span className="text-sm text-gray-200">{c.full_name || c.email}</span>
                    {c.company && (
                      <span className="text-xs text-gray-500">{c.company}</span>
                    )}
                    {match && (
                      <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
                        match.confidence === "high"
                          ? "text-green-400 border-green-800 bg-green-900/20"
                          : "text-yellow-400 border-yellow-800 bg-yellow-900/20"
                      }`}>
                        {match.confidence === "high" ? "Matched" : "Partial match"}
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-gray-600">{c.email}</span>
                  {match && (
                    <div className="text-[10px] text-gray-500 mt-0.5">{match.reason}</div>
                  )}
                  {c.interests && c.interests.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {c.interests.map((tag) => (
                        <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-[#2a2a4a] text-gray-400">{tag}</span>
                      ))}
                    </div>
                  )}
                </div>
              </label>
            );
          })}
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200 text-sm px-3 py-1.5 rounded hover:bg-[#1a1a2e] transition-colors">Cancel</button>
          <button onClick={onSend} disabled={sending} className="bg-[#38BDF8] hover:bg-[#FFD700] disabled:opacity-50 text-[#2E2E38] text-sm font-semibold px-4 py-1.5 rounded transition-colors">
            {sending ? "Sending…" : selectedIds.length > 0 ? `Send to ${selectedIds.length}` : "Send to all"}
          </button>
        </div>
      </div>
    </div>
  );
}


// ─── Main Component ───────────────────────────────────────────────────────────

export default function AdvisoryEditor({
  advisory,
  onSave,
  onApprove,
  onClose,
  onSend,
  onDone,
}) {
  const [form, setForm] = useState(advisory);
  const [previewHtml, setPreviewHtml] = useState("");
  const [previewLoading, setPreviewLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [approving, setApproving] = useState(false);
  const [closing, setClosing] = useState(false);
  const [sending, setSending] = useState(false);
  const [showSendModal, setShowSendModal] = useState(false);
  const [showNoteModal, setShowNoteModal] = useState(false);
  const [validationErrors, setValidationErrors] = useState([]);
  const [translating, setTranslating] = useState(null); // field name being translated
  const [invalidFields, setInvalidFields] = useState(new Set());
  const [clients, setClients] = useState([]);
  const [selectedClientIds, setSelectedClientIds] = useState([]);
  const debounceRef = useRef(null);
  const { addToast } = useToast();

  // ── Lock body scroll and reset scroll position when editor opens ──
  useEffect(() => {
    window.scrollTo(0, 0);
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = ""; };
  }, []);

  // ── Load clients for send modal and pre-select matched ones ──
  useEffect(() => {
    api
      .get("/api/proposals/clients")
      .then((res) => {
        const allClients = res.data || [];
        setClients(allClients);
        // Pre-select every matched client, regardless of match confidence
        // (high and partial are treated equally).
        const matches = advisory.clientMatches || [];
        if (matches.length > 0) {
          const matchedIds = matches
            .map(m => m.client_id)
            .filter(id => allClients.some(c => c.id === id));
          setSelectedClientIds(matchedIds);
        }
      })
      .catch(() => {});
  }, [advisory.clientMatches]);

  // ── Debounced live preview ──
  const refreshPreview = useCallback(async (currentForm) => {
    setPreviewLoading(true);
    try {
      const res = await api.post("/api/advisory/preview", buildPreviewPayload(currentForm));
      setPreviewHtml(res.data.html || "");
    } catch {
      // silent — preview is best-effort
    } finally {
      setPreviewLoading(false);
    }
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => refreshPreview(form), 700);
    return () => clearTimeout(debounceRef.current);
  }, [form, refreshPreview]);


  // ── Field helpers ──
  const setField = (key, value) => {
    setForm((f) => ({ ...f, [key]: value }));
    if (validationErrors.length) setValidationErrors([]);
    if (invalidFields.has(key)) setInvalidFields((s) => { const n = new Set(s); n.delete(key); return n; });
  };

  // ── Actions ──
  // Saves and merges any returned fields (e.g. new IDs from record creation)
  const saveAndMerge = async (currentForm) => {
    const updates = await onSave(currentForm);
    if (updates && typeof updates === "object") {
      setForm((f) => ({ ...f, ...updates }));
      return { ...currentForm, ...updates };
    }
    return currentForm;
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await saveAndMerge(form);
      addToast("Saved.", "success");
    } catch (e) {
      addToast(errorMessage(e, "Failed to save."), "error");
      throw e;
    } finally {
      setSaving(false);
    }
  };

  const handleApprove = async () => {
    setApproving(true);
    try {
      await saveAndMerge(form);
      await onApprove(form);
      addToast("Marked as done.", "success");
      onDone?.();
    } catch (e) {
      addToast(errorMessage(e, "Failed."), "error");
    } finally {
      setApproving(false);
    }
  };

  const handleClose = async () => {
    setClosing(true);
    try {
      await onClose(form);
      addToast("Ticket closed.", "info");
      onDone?.();
    } catch (e) {
      addToast(errorMessage(e, "Failed to close."), "error");
    } finally {
      setClosing(false);
    }
  };

  // Returns { messages: string[], fields: string[] }
  const validateForm = (f) => {
    const messages = [];
    const fields = [];
    if (!(f.title || "").trim()) { messages.push("Title is required"); fields.push("title"); }
    if (!(f.summary || "").trim()) { messages.push("Executive summary is required"); fields.push("summary"); }
    if (f.kind === "news") {
      if (!(f.description || "").trim() || (f.description || "").trim().length < 20)
        { messages.push("Description is required (minimum 20 characters)"); fields.push("description"); }
      if (!(f.sectors || []).length) { messages.push("At least one sector is required"); fields.push("sectors"); }
    } else {
      if (!(f.description || "").trim() || (f.description || "").trim().length < 20)
        { messages.push("Description is required (minimum 20 characters)"); fields.push("description"); }
      if (f.kind === "threat") {
        if (!(f.severity || "").trim()) { messages.push("Severity is required"); fields.push("severity"); }
      }
    }
    return { messages, fields };
  };

  const handleOpenSendModal = () => {
    const { messages, fields } = validateForm(form);
    if (messages.length > 0) {
      setValidationErrors(messages);
      setInvalidFields(new Set(fields));
      // Scroll to and focus the first missing field
      const firstId = `editor-field-${fields[0]}`;
      setTimeout(() => {
        const el = document.getElementById(firstId);
        if (el) { el.scrollIntoView({ behavior: "smooth", block: "center" }); el.focus(); }
      }, 50);
      return;
    }
    setValidationErrors([]);
    setInvalidFields(new Set());
    setShowSendModal(true);
  };

  const handleSend = async () => {
    setSending(true);
    try {
      // Save latest edits first; capture any new IDs (e.g. freshly-created records)
      const latestForm = await saveAndMerge(form);
      const result = await onSend(latestForm, selectedClientIds);
      addToast(
        `Advisory sent to ${result?.sent_to ?? (selectedClientIds.length || "all")} recipient(s).`,
        "success"
      );
      setShowSendModal(false);
      onDone?.();
    } catch (e) {
      addToast(errorMessage(e, "Failed to send advisory."), "error");
    } finally {
      setSending(false);
    }
  };

  const toggleClient = (id) =>
    setSelectedClientIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );

  const translateText = async (text) => {
    if (!text || !text.trim()) return text;
    const res = await api.post("/api/advisory/translate", { text, field: "bulk" });
    const translated = res.data.translated || "";
    return (translated && translated !== text) ? translated : text;
  };


  const handleTranslateAll = async () => {
    setTranslating("all");
    let count = 0;
    try {
      // Text fields
      for (const field of ["title", "summary", "description"]) {
        const text = form[field] || "";
        if (!text.trim()) continue;
        const result = await translateText(text);
        if (result !== text) { setField(field, result); count++; }
      }
      // Impact points
      const impacts = form.impactPoints || [];
      if (impacts.length > 0) {
        const translated = [];
        for (const pt of impacts) {
          translated.push(await translateText(pt));
        }
        if (JSON.stringify(translated) !== JSON.stringify(impacts)) {
          setField("impactPoints", translated); count++;
        }
      }
      // Remediation steps
      const steps = form.remediationSteps || [];
      if (steps.length > 0) {
        const translated = [];
        for (const s of steps) {
          const action = await translateText(s.action || "");
          translated.push({ ...s, action });
        }
        if (JSON.stringify(translated) !== JSON.stringify(steps)) {
          setField("remediationSteps", translated); count++;
        }
      }
      // Temp mitigation
      const mitigations = form.tempMitigation || [];
      if (mitigations.length > 0) {
        const translated = [];
        for (const pt of mitigations) {
          translated.push(await translateText(pt));
        }
        if (JSON.stringify(translated) !== JSON.stringify(mitigations)) {
          setField("tempMitigation", translated); count++;
        }
      }
      // Product versions & notes
      const products = form.enrichedProducts || [];
      if (products.length > 0) {
        const translated = [];
        for (const p of products) {
          const versions = await translateText(p.versions || "");
          const notes = await translateText(p.notes || "");
          translated.push({ ...p, versions, notes });
        }
        if (JSON.stringify(translated) !== JSON.stringify(products)) {
          setField("enrichedProducts", translated); count++;
        }
      }
      addToast(count > 0 ? `Translated ${count} field(s) to English.` : "All fields already in English.", count > 0 ? "success" : "info");
    } catch (e) {
      addToast(errorMessage(e, "Translation failed."), "error");
    } finally {
      setTranslating(null);
    }
  };

  // ── Severity badge ──
  const severityLabel =
    form.kind === "cve"
      ? form.cvssSeverity || "—"
      : form.kind === "news"
      ? form.source || "NEWS"
      : form.severity || "—";

  const severityColor = form.kind === "news"
    ? "text-cyan-400 bg-cyan-900/20 border-cyan-800"
    : ({
        CRITICAL: "text-red-400 bg-red-900/20 border-red-800",
        HIGH: "text-orange-400 bg-orange-900/20 border-orange-800",
        MEDIUM: "text-yellow-400 bg-yellow-900/20 border-yellow-800",
        LOW: "text-green-400 bg-green-900/20 border-green-800",
      }[severityLabel.toUpperCase()] || "text-gray-400 bg-gray-800/20 border-gray-700");

  return (
    <div className="fixed inset-0 z-50 bg-[#0a0a15] flex flex-col">
      {/* ── Header bar ── */}
      <div className="flex items-center justify-between px-5 py-2.5 bg-[#12121e] border-b border-[#2a2a4a] shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-[#38BDF8] font-bold text-sm tracking-wide">
            Advisory Editor
          </span>
          <span
            className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
              form.kind === "cve"
                ? "text-blue-300 bg-blue-900/20 border-blue-800"
                : form.kind === "news"
                ? "text-cyan-300 bg-cyan-900/20 border-cyan-800"
                : "text-purple-300 bg-purple-900/20 border-purple-800"
            }`}
          >
            {form.kind === "cve" ? "CVE" : form.kind === "news" ? "NEWS" : "THREAT"}
          </span>
          <span
            className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${severityColor}`}
          >
            {severityLabel.toUpperCase()}
          </span>
          {form.origin && (
            <span className="text-[10px] text-gray-600">
              {form.origin === "SCRAPER" ? "System flagged" : "Analyst flagged"}
            </span>
          )}
          {form.flagNote && (
            <button
              onClick={() => setShowNoteModal(true)}
              className="text-[9px] px-2 py-0.5 rounded border border-[#38BDF8]/40 bg-[#38BDF8]/10 text-[#38BDF8] hover:bg-[#38BDF8]/20 shrink-0"
            >
              Note
            </button>
          )}
          {advisory.advisory_sent_at && (
            <span
              title={`Sent by ${advisory.advisory_sent_by || "unknown"} on ${new Date(advisory.advisory_sent_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })}`}
              className="text-[9px] px-1.5 py-0.5 rounded border bg-green-900/30 text-green-400 border-green-700/50 cursor-default"
            >
              SENT
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Translate All */}
          <button
            onClick={handleTranslateAll}
            disabled={translating === "all"}
            className="text-[10px] px-2.5 py-1.5 rounded border border-blue-800 text-blue-400 hover:bg-blue-900/20 disabled:opacity-50 transition-colors"
          >
            {translating === "all" ? "Translating…" : "Translate"}
          </button>

          {/* Save */}
          <button
            onClick={handleSave}
            disabled={saving}
            className="bg-[#2a2a4a] hover:bg-[#3a3a5a] disabled:opacity-50 text-gray-200 text-xs font-medium px-3 py-1.5 rounded transition-colors"
          >
            {saving ? "Saving…" : "Save Draft"}
          </button>

          {/* Send */}
          <button
            onClick={handleOpenSendModal}
            className="bg-[#38BDF8] hover:bg-[#FFD700] text-[#2E2E38] text-xs font-bold px-3 py-1.5 rounded transition-colors"
          >
            Send Advisory
          </button>

          {/* Mark done (approve proposal) */}
          {form.proposalId && (
            <button
              onClick={handleApprove}
              disabled={approving}
              className="text-green-400 hover:text-green-200 text-xs px-3 py-1.5 rounded border border-green-800 hover:border-green-600 hover:bg-green-900/20 disabled:opacity-50 transition-colors"
            >
              {approving ? "…" : "Mark Done"}
            </button>
          )}

          {/* Discard / close */}
          {form.proposalId && (
            <button
              onClick={handleClose}
              disabled={closing}
              className="text-red-400 hover:text-red-200 text-xs px-3 py-1.5 rounded border border-red-900 hover:border-red-700 hover:bg-red-900/20 disabled:opacity-50 transition-colors"
            >
              {closing ? "…" : "Discard"}
            </button>
          )}

          {/* Close editor */}
          <button
            onClick={onDone}
            className="text-gray-500 hover:text-gray-300 text-lg leading-none px-1 transition-colors"
            title="Close editor"
          >
            ✕
          </button>
        </div>
      </div>

      {/* ── Validation errors ── */}
      {validationErrors.length > 0 && (
        <div className="mx-5 mt-2 p-3 bg-red-900/20 border border-red-800 rounded text-sm">
          <p className="text-red-400 font-semibold text-xs mb-1">Cannot send — fix the following:</p>
          <ul className="list-disc list-inside text-red-300 text-xs space-y-0.5">
            {validationErrors.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}

      {/* ── Two-panel body ── */}
      <div className="flex flex-1 overflow-hidden">

        {/* Left panel — editable form */}
        <div className="w-1/2 overflow-y-auto p-5 space-y-4 border-r border-[#2a2a4a]">

          {/* Advisory metadata row */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Advisory ID</FieldLabel>
              <input
                className={inputCls}
                value={form.advisoryId || ""}
                onChange={(e) => setField("advisoryId", e.target.value)}
                placeholder="e.g. 260421"
              />
            </div>
            <div>
              <FieldLabel>Published Date (display)</FieldLabel>
              <input
                className={inputCls}
                value={form.publishedAt || ""}
                onChange={(e) => setField("publishedAt", e.target.value)}
                placeholder="e.g. 21 April 2026"
              />
            </div>
          </div>

          {/* Title */}
          <div>
            <FieldLabel required>Title</FieldLabel>
            <input
              id="editor-field-title"
              className={`${inputCls} ${invalidFields.has("title") ? "border-red-600" : ""}`}
              value={form.title || ""}
              onChange={(e) => setField("title", e.target.value)}
              placeholder="Vulnerability or threat title"
            />
          </div>

          {/* Summary */}
          <div>
            <FieldLabel required>Executive Summary</FieldLabel>
            <textarea
              id="editor-field-summary"
              className={`${textareaCls} ${invalidFields.has("summary") ? "border-red-600" : ""}`}
              rows={4}
              value={form.summary || ""}
              onChange={(e) => setField("summary", e.target.value)}
              placeholder="Context paragraph that opens the advisory — who disclosed it, what it affects, overall situation…"
            />
          </div>

          {/* Technical description */}
          <div>
            <FieldLabel required>Technical Description</FieldLabel>
            <textarea
              id="editor-field-description"
              className={`${textareaCls} ${invalidFields.has("description") ? "border-red-600" : ""}`}
              rows={3}
              value={form.description || ""}
              onChange={(e) => setField("description", e.target.value)}
              placeholder="Detailed technical description of the vulnerability or threat"
            />
          </div>

          {/* ── CVE-specific fields ── */}
          {form.kind === "cve" && (
            <>
              <SectionHeading>CVE Details</SectionHeading>

              <div>
                <FieldLabel>CVE IDs</FieldLabel>
                <input
                  className={inputCls}
                  value={form.cveIds || ""}
                  onChange={(e) => setField("cveIds", e.target.value)}
                  placeholder="CVE-2026-12345, CVE-2026-12346"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <FieldLabel>CVSS Score (0–10)</FieldLabel>
                  <input
                    type="number"
                    min="0"
                    max="10"
                    step="0.1"
                    className={inputCls}
                    value={form.cvssScore ?? ""}
                    onChange={(e) =>
                      setField(
                        "cvssScore",
                        e.target.value !== "" ? parseFloat(e.target.value) : null
                      )
                    }
                    placeholder="e.g. 9.8"
                  />
                </div>
                <div>
                  <FieldLabel>CVSS Severity</FieldLabel>
                  <select
                    className={selectCls}
                    value={form.cvssSeverity || ""}
                    onChange={(e) => setField("cvssSeverity", e.target.value)}
                  >
                    <option value="">— Select —</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <FieldLabel>Vendor</FieldLabel>
                  <input
                    className={inputCls}
                    value={form.vendor || ""}
                    onChange={(e) => setField("vendor", e.target.value)}
                    placeholder="e.g. Microsoft, IBM"
                  />
                </div>
                <div>
                  <FieldLabel>CVSS Vector</FieldLabel>
                  <input
                    className={inputCls}
                    value={form.cvssVector || ""}
                    onChange={(e) => setField("cvssVector", e.target.value)}
                    placeholder="CVSS:3.1/AV:N/…"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <FieldLabel>Patch Available</FieldLabel>
                  <select
                    className={selectCls}
                    value={form.patchAvailable || "unknown"}
                    onChange={(e) => setField("patchAvailable", e.target.value)}
                  >
                    <option value="unknown">Unknown</option>
                    <option value="yes">Yes</option>
                    <option value="no">No</option>
                  </select>
                </div>
                <div>
                  <FieldLabel>Exploit Available</FieldLabel>
                  <select
                    className={selectCls}
                    value={form.exploitAvailable || "unknown"}
                    onChange={(e) => setField("exploitAvailable", e.target.value)}
                  >
                    <option value="unknown">Unknown</option>
                    <option value="yes">Yes</option>
                    <option value="no">No</option>
                  </select>
                </div>
              </div>

              <div>
                <FieldLabel>Patch / Fix URL</FieldLabel>
                <input
                  className={inputCls}
                  value={form.patchUrl || ""}
                  onChange={(e) => setField("patchUrl", e.target.value)}
                  placeholder="https://…"
                />
              </div>

              <div>
                <FieldLabel>Source URL</FieldLabel>
                <input
                  className={inputCls}
                  value={form.sourceUrl || ""}
                  onChange={(e) => setField("sourceUrl", e.target.value)}
                  placeholder="https://…"
                />
              </div>
            </>
          )}

          {/* ── Threat-specific fields ── */}
          {form.kind === "threat" && (
            <>
              <SectionHeading>Threat Details</SectionHeading>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <FieldLabel>Risk Score (0–100)</FieldLabel>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    step="1"
                    className={inputCls}
                    value={form.riskScore ?? ""}
                    onChange={(e) =>
                      setField(
                        "riskScore",
                        e.target.value !== "" ? parseFloat(e.target.value) : null
                      )
                    }
                    placeholder="e.g. 85"
                  />
                </div>
                <div>
                  <FieldLabel required>Severity</FieldLabel>
                  <select
                    id="editor-field-severity"
                    className={`${selectCls} ${invalidFields.has("severity") ? "border-red-600" : ""}`}
                    value={form.severity || ""}
                    onChange={(e) => setField("severity", e.target.value)}
                  >
                    <option value="">— Select —</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <FieldLabel>Threat Type</FieldLabel>
                  <input
                    className={inputCls}
                    value={form.threatType || ""}
                    onChange={(e) => setField("threatType", e.target.value)}
                    placeholder="e.g. Ransomware, APT, Phishing"
                  />
                </div>
                <div>
                  <FieldLabel>Regions</FieldLabel>
                  <input
                    className={inputCls}
                    value={form.regions || ""}
                    onChange={(e) => setField("regions", e.target.value)}
                    placeholder="e.g. Global, MENA, Europe"
                  />
                </div>
              </div>

              <div>
                <FieldLabel>TTP Codes (MITRE ATT&amp;CK)</FieldLabel>
                <input
                  className={inputCls}
                  value={form.ttpCodes || ""}
                  onChange={(e) => setField("ttpCodes", e.target.value)}
                  placeholder="e.g. T1059.001, T1078, T1486"
                />
              </div>

              <div>
                <FieldLabel>Source URL</FieldLabel>
                <input
                  className={inputCls}
                  value={form.sourceUrl || ""}
                  onChange={(e) => setField("sourceUrl", e.target.value)}
                  placeholder="https://…"
                />
              </div>
            </>
          )}

          {/* ── News-specific fields ── */}
          {form.kind === "news" && (
            <>
              <SectionHeading>News Details</SectionHeading>

              {/* Source (read-only) */}
              {form.source && (
                <div>
                  <FieldLabel>Source</FieldLabel>
                  <p className="text-sm text-gray-300 bg-[#0f0f1f] border border-[#2a2a4a] rounded px-3 py-1.5">{form.source}</p>
                </div>
              )}

              {/* URL (read-only, linked) */}
              {form.sourceUrl && (
                <div>
                  <FieldLabel>Original Article</FieldLabel>
                  <a
                    href={form.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-blue-400 hover:text-blue-300 underline break-all"
                  >
                    {form.sourceUrl}
                  </a>
                </div>
              )}

              {/* Language badge */}
              {form.language && form.language !== "en" && (
                <span className="text-[10px] px-2 py-0.5 rounded border border-yellow-700 text-yellow-400 bg-yellow-900/20 font-semibold uppercase">
                  {form.language}
                </span>
              )}

              {/* Sectors tag input */}
              <div id="editor-field-sectors">
                <FieldLabel required>Sectors</FieldLabel>
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {(form.sectors || []).map((s, i) => (
                    <span key={i} className="flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-[#2E2E38] text-[#38BDF8] border border-[#38BDF8]/30">
                      {s}
                      <button
                        onClick={() => setField("sectors", form.sectors.filter((_, j) => j !== i))}
                        className="text-[#38BDF8]/60 hover:text-red-400 text-sm leading-none"
                      >×</button>
                    </span>
                  ))}
                </div>
                <select
                  className={selectCls}
                  value=""
                  onChange={(e) => {
                    if (e.target.value && !(form.sectors || []).includes(e.target.value)) {
                      setField("sectors", [...(form.sectors || []), e.target.value]);
                    }
                  }}
                >
                  <option value="">+ Add sector…</option>
                  {SECTOR_OPTIONS.filter(s => !(form.sectors || []).includes(s)).map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
            </>
          )}

          {/* ── Enrichment sections — shared (CVE/Threat only) ── */}
          {form.kind !== "news" && (<>
          <ProductsEditor
            value={form.enrichedProducts || []}
            onChange={(v) => setField("enrichedProducts", v)}
          />

          <BulletsEditor
            label="Impact"
            value={form.impactPoints || []}
            onChange={(v) => setField("impactPoints", v)}
            placeholder="Add impact point (press Enter to confirm)…"
          />

          <RemediationEditor
            value={form.remediationSteps || []}
            onChange={(v) => setField("remediationSteps", v)}
          />

          <BulletsEditor
            label="Temporary Mitigation"
            value={form.tempMitigation || []}
            onChange={(v) => setField("tempMitigation", v)}
            placeholder="Add mitigation measure…"
          />

          <ResourcesEditor
            value={form.additionalResources || []}
            onChange={(v) => setField("additionalResources", v)}
          />
          </>)}

          {/* Bottom padding */}
          <div className="h-6" />
        </div>

        {/* Right panel — live email preview */}
        <div className="w-1/2 flex flex-col bg-[#f4f4f4]">
          <div className="flex items-center justify-between px-4 py-2 bg-[#12121e] border-b border-[#2a2a4a] shrink-0">
            <span className="text-[10px] font-semibold uppercase tracking-widest text-gray-500">
              Email Preview
            </span>
            {previewLoading && (
              <span className="text-[10px] text-gray-600 animate-pulse">Updating…</span>
            )}
          </div>
          <div className="flex-1 overflow-hidden">
            {previewHtml ? (
              <iframe
                srcDoc={previewHtml}
                title="Advisory email preview"
                className="w-full h-full border-0"
                sandbox="allow-same-origin"
              />
            ) : (
              <div className="flex items-center justify-center h-full">
                <span className="text-gray-400 text-sm">Loading preview…</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Send Modal ── */}
      {showSendModal && (
        <SendModal
          clients={clients}
          selectedIds={selectedClientIds}
          onToggle={toggleClient}
          onSend={handleSend}
          onClose={() => setShowSendModal(false)}
          sending={sending}
          clientMatches={advisory.clientMatches || []}
        />
      )}

      {showNoteModal && (
        <div
          className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
          onClick={() => setShowNoteModal(false)}
        >
          <div
            className="bg-[#12121e] border border-[#38BDF8]/30 rounded-lg p-5 w-full max-w-sm shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <p className="text-[10px] uppercase tracking-wider text-[#38BDF8]/60 mb-3">Analyst Note</p>
            <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">{form.flagNote}</p>
            <button
              onClick={() => setShowNoteModal(false)}
              className="mt-4 w-full px-4 py-2 text-xs rounded bg-[#1a1a2e] border border-[#2a2a4a] text-gray-400 hover:text-gray-200"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
