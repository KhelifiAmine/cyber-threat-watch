import React, { useState, useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import api from "../api/axios";
import { useToast } from "../context/ToastContext";
import { errorMessage } from "../api/errors";

const inputCls =
  "w-full bg-[#0f0f1f] border border-[#2a2a4a] rounded px-3 py-1.5 text-sm text-gray-200 outline-none focus:border-[#38BDF8]/40 placeholder-gray-700 transition-colors";

// ─── Inventory Preview Modal (Excel upload confirmation) ──

// removed_entries: items in current inventory but NOT in the file.
// By default we keep them (additive merge). Analyst checks the ones they want to remove.
function InventoryPreviewModal({ preview, currentInventory, clientName, onConfirm, onClose, confirming }) {
  // Set of indices into preview.removed_entries that the analyst wants to actually remove
  const [removeSet, setRemoveSet] = useState(new Set());
  if (!preview) return null;

  const toggleRemove = (i) => setRemoveSet((s) => {
    const n = new Set(s);
    n.has(i) ? n.delete(i) : n.add(i);
    return n;
  });

  const handleConfirm = () => {
    const removedEntries = preview.removed_entries || [];
    // Items to remove: only those the analyst explicitly checked
    const toRemoveSet = new Set(
      removedEntries
        .filter((_, i) => removeSet.has(i))
        .map((e) => `${e.vendor}|${e.product_raw}|${e.version || ""}`)
    );
    // Start from current inventory, drop checked removals, then add new entries
    const kept = (currentInventory || []).filter(
      (p) => !toRemoveSet.has(`${p.vendor}|${p.product_raw}|${p.version || ""}`)
    );
    const finalInventory = [...kept, ...(preview.new_entries || [])];
    onConfirm(finalInventory);
  };

  const removedCount = preview.removed_entries?.length || 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg w-[600px] max-h-[80vh] flex flex-col p-6 shadow-2xl">
        <h3 className="text-white font-semibold text-sm mb-1">
          Inventory Preview — {clientName}
        </h3>
        <p className="text-[10px] text-gray-500 mb-4">
          New products are always added. Products not in the file are kept by default — check the ones you want to remove.
        </p>

        <div className="flex items-center gap-4 mb-4 text-sm">
          <span className="text-green-400 font-semibold">{preview.new_entries?.length || 0} new</span>
          <span className="text-gray-400">{preview.unchanged_count || 0} unchanged</span>
          {removedCount > 0 && (
            <span className="text-yellow-400">{removedCount} not in file ({removeSet.size} selected to remove)</span>
          )}
          <span className="text-gray-500">({preview.parsed_count} in file)</span>
        </div>

        {preview.unrecognized_vendors?.length > 0 && (
          <div className="mb-3 p-2 rounded bg-yellow-900/20 border border-yellow-800 text-xs text-yellow-400">
            Unrecognized vendors: {preview.unrecognized_vendors.join(", ")}
            <span className="text-yellow-600 ml-1">(stored as-is)</span>
          </div>
        )}

        <div className="flex-1 overflow-y-auto mb-4 space-y-3">
          {preview.new_entries?.length > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-green-400 mb-1">New (will be added)</h4>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500">
                    <th className="text-left px-2 py-1">Vendor</th>
                    <th className="text-left px-2 py-1">Product</th>
                    <th className="text-left px-2 py-1">Family</th>
                    <th className="text-left px-2 py-1">Version</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.new_entries.map((e, i) => (
                    <tr key={i} className="text-gray-300 border-t border-[#1e1e3a]">
                      <td className="px-2 py-1">{e.vendor}</td>
                      <td className="px-2 py-1">{e.product_raw}</td>
                      <td className="px-2 py-1 text-gray-500">{e.product_family}</td>
                      <td className="px-2 py-1 font-mono">{e.version || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {removedCount > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-yellow-400 mb-1">
                Not in file — check to remove
              </h4>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500">
                    <th className="w-6 px-1" />
                    <th className="text-left px-2 py-1">Vendor</th>
                    <th className="text-left px-2 py-1">Product</th>
                    <th className="text-left px-2 py-1">Version</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.removed_entries.map((e, i) => (
                    <tr key={i} className={`border-t border-[#1e1e3a] ${removeSet.has(i) ? "text-red-400 line-through opacity-60" : "text-gray-400"}`}>
                      <td className="px-1 py-1.5">
                        <input
                          type="checkbox"
                          checked={removeSet.has(i)}
                          onChange={() => toggleRemove(i)}
                          className="accent-red-500"
                          title="Check to remove this product"
                        />
                      </td>
                      <td className="px-2 py-1">{e.vendor}</td>
                      <td className="px-2 py-1">{e.product_raw}</td>
                      <td className="px-2 py-1 font-mono">{e.version || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-[#2a2a4a]">
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-200 text-sm px-3 py-1.5 rounded hover:bg-[#1a1a2e] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={confirming}
            className="bg-[#38BDF8] hover:bg-[#FFD700] disabled:opacity-50 text-[#2E2E38] text-sm font-semibold px-4 py-1.5 rounded transition-colors"
          >
            {confirming ? "Saving…" : removeSet.size > 0 ? `Save (add ${preview.new_entries?.length || 0}, remove ${removeSet.size})` : `Save (add ${preview.new_entries?.length || 0})`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Import Preview Modal (bulk client import) ──────────

function ImportPreviewModal({ preview, onConfirm, onClose, confirming }) {
  const [selectedNew, setSelectedNew] = useState(() =>
    new Set((preview?.new_clients || []).map((_, i) => i))
  );
  const [selectedUpdates, setSelectedUpdates] = useState(() =>
    new Set((preview?.existing_updates || []).map((_, i) => i))
  );

  if (!preview) return null;

  const toggleNew = (i) => setSelectedNew((s) => {
    const next = new Set(s);
    next.has(i) ? next.delete(i) : next.add(i);
    return next;
  });
  const toggleUpdate = (i) => setSelectedUpdates((s) => {
    const next = new Set(s);
    next.has(i) ? next.delete(i) : next.add(i);
    return next;
  });

  const handleConfirm = () => {
    const newClients = preview.new_clients.filter((_, i) => selectedNew.has(i));
    const applyUpdates = preview.existing_updates
      .filter((_, i) => selectedUpdates.has(i))
      .map((u) => {
        const upd = { id: u.id };
        if (u.changes.company) upd.company = u.changes.company.new;
        if (u.changes.role) upd.role = u.changes.role.new;
        if (u.changes.interests) {
          const oldSet = new Set(u.changes.interests.removed || []);
          const current = (preview.existing_updates.find((x) => x.id === u.id)?.changes?.interests?.added || []);
          // Merge: keep items not removed, add new ones
          upd.interests = current;
        }
        return upd;
      });
    onConfirm(newClients, applyUpdates);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg w-[700px] max-h-[80vh] flex flex-col p-6 shadow-2xl">
        <h3 className="text-white font-semibold text-sm mb-4">Import Preview</h3>

        <div className="flex items-center gap-4 mb-4 text-sm">
          <span className="text-green-400 font-semibold">{preview.new_clients.length} new</span>
          <span className="text-blue-400">{preview.existing_updates.length} updates</span>
          <span className="text-gray-400">{preview.unchanged.length} unchanged</span>
          {preview.errors.length > 0 && (
            <span className="text-red-400">{preview.errors.length} errors</span>
          )}
        </div>

        <div className="flex-1 overflow-y-auto mb-4 space-y-4">
          {/* New Clients */}
          {preview.new_clients.length > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-green-400 mb-1">New Clients</h4>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500">
                    <th className="w-6 px-1" />
                    <th className="text-left px-2 py-1">Email</th>
                    <th className="text-left px-2 py-1">Name</th>
                    <th className="text-left px-2 py-1">Company</th>
                    <th className="text-left px-2 py-1">Alert Level</th>
                    <th className="text-left px-2 py-1">Interests</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.new_clients.map((c, i) => (
                    <tr key={i} className="text-gray-300 border-t border-[#1e1e3a]">
                      <td className="px-1">
                        <input type="checkbox" checked={selectedNew.has(i)} onChange={() => toggleNew(i)} className="accent-[#38BDF8]" />
                      </td>
                      <td className="px-2 py-1">{c.email}</td>
                      <td className="px-2 py-1">{c.full_name}</td>
                      <td className="px-2 py-1 text-gray-400">{c.company || "—"}</td>
                      <td className="px-2 py-1">{c.role}</td>
                      <td className="px-2 py-1">
                        <div className="flex flex-wrap gap-0.5">
                          {(c.interests || []).map((t) => (
                            <span key={t} className="text-[9px] px-1 py-0.5 rounded bg-[#2a2a4a] text-gray-300">{t}</span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Updates */}
          {preview.existing_updates.length > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-blue-400 mb-1">Updates to Existing</h4>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500">
                    <th className="w-6 px-1" />
                    <th className="text-left px-2 py-1">Email</th>
                    <th className="text-left px-2 py-1">Name</th>
                    <th className="text-left px-2 py-1">Changes</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.existing_updates.map((u, i) => (
                    <tr key={i} className="text-gray-300 border-t border-[#1e1e3a]">
                      <td className="px-1">
                        <input type="checkbox" checked={selectedUpdates.has(i)} onChange={() => toggleUpdate(i)} className="accent-[#38BDF8]" />
                      </td>
                      <td className="px-2 py-1">{u.email}</td>
                      <td className="px-2 py-1">{u.full_name}</td>
                      <td className="px-2 py-1">
                        <div className="flex flex-wrap gap-1">
                          {u.changes.company && (
                            <span className="text-[9px] px-1 py-0.5 rounded bg-blue-900/30 text-blue-300">
                              company: "{u.changes.company.old}" → "{u.changes.company.new}"
                            </span>
                          )}
                          {u.changes.role && (
                            <span className="text-[9px] px-1 py-0.5 rounded bg-blue-900/30 text-blue-300">
                              alert: {u.changes.role.old} → {u.changes.role.new}
                            </span>
                          )}
                          {u.changes.interests?.added?.map((t) => (
                            <span key={`+${t}`} className="text-[9px] px-1 py-0.5 rounded bg-green-900/30 text-green-300">+{t}</span>
                          ))}
                          {u.changes.interests?.removed?.map((t) => (
                            <span key={`-${t}`} className="text-[9px] px-1 py-0.5 rounded bg-red-900/30 text-red-300">-{t}</span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Unchanged */}
          {preview.unchanged.length > 0 && (
            <div className="text-xs text-gray-500">
              {preview.unchanged.length} client{preview.unchanged.length !== 1 ? "s" : ""} already up to date
            </div>
          )}

          {/* Errors */}
          {preview.errors.length > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-red-400 mb-1">Errors</h4>
              <div className="space-y-0.5">
                {preview.errors.map((e, i) => (
                  <div key={i} className="text-xs text-red-300">Row {e.row}: {e.reason}</div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-[#2a2a4a]">
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200 text-sm px-3 py-1.5 rounded hover:bg-[#1a1a2e] transition-colors">
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={confirming || (selectedNew.size === 0 && selectedUpdates.size === 0)}
            className="bg-[#38BDF8] hover:bg-[#FFD700] disabled:opacity-50 text-[#2E2E38] text-sm font-semibold px-4 py-1.5 rounded transition-colors"
          >
            {confirming ? "Importing…" : `Import ${selectedNew.size} new, update ${selectedUpdates.size} existing`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Inline product add / edit form ──────────────────────

function ProductForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(
    initial
      ? { ...initial }
      : { vendor: "", product_raw: "", product_family: "", version: "" }
  );
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!form.vendor.trim() || !form.product_raw.trim()) return;
    onSave({
      vendor: form.vendor.trim(),
      vendor_raw: form.vendor.trim(),
      product_raw: form.product_raw.trim(),
      product_family: form.product_family.trim() || form.product_raw.trim(),
      version: form.version.trim(),
    });
  };

  return (
    <tr className="bg-[#0a0a18]">
      <td className="px-2 py-1.5" />
      <td className="px-2 py-1.5">
        <input
          className={inputCls + " text-xs py-1"}
          placeholder="Vendor *"
          value={form.vendor}
          onChange={(e) => set("vendor", e.target.value)}
          autoFocus
        />
      </td>
      <td className="px-2 py-1.5">
        <input
          className={inputCls + " text-xs py-1"}
          placeholder="Product name *"
          value={form.product_raw}
          onChange={(e) => set("product_raw", e.target.value)}
        />
      </td>
      <td className="px-2 py-1.5">
        <input
          className={inputCls + " text-xs py-1"}
          placeholder="Family (optional)"
          value={form.product_family}
          onChange={(e) => set("product_family", e.target.value)}
        />
      </td>
      <td className="px-2 py-1.5">
        <input
          className={inputCls + " text-xs py-1 font-mono"}
          placeholder="Version"
          value={form.version}
          onChange={(e) => set("version", e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSubmit(e)}
        />
      </td>
      <td className="px-2 py-1.5">
        <div className="flex gap-1">
          <button
            type="button"
            onClick={handleSubmit}
            className="text-[10px] font-semibold px-2.5 py-1 rounded bg-[#38BDF8]/10 text-[#38BDF8] border border-[#38BDF8]/30 hover:bg-[#38BDF8]/20 transition-colors"
          >
            {initial ? "Save" : "Add"}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="text-[10px] px-2 py-1 rounded text-gray-500 hover:text-gray-300 hover:bg-[#1a1a2e] transition-colors"
          >
            Cancel
          </button>
        </div>
      </td>
    </tr>
  );
}

// ─── Edit Client Modal ────────────────────────────────────

const ALLOWED_SECTORS = [
  "Banking & Finance", "Energy & Utilities", "Healthcare", "Telecom",
  "Government", "Manufacturing", "Retail", "Education",
  "Transportation", "Technology",
];

const ALLOWED_REGIONS = [
  "Middle East", "MENA", "Europe", "North America",
  "Asia-Pacific", "Africa", "Latin America", "Global",
];

function EditClientModal({ client, onSave, onClose }) {
  const [form, setForm] = useState({
    full_name: client.full_name || "",
    email: client.email || "",
    company: client.company || "",
    interests: client.interests || [],
    regions: client.regions || [],
    is_active: client.is_active ?? true,
  });
  const [saving, setSaving] = useState(false);

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const toggleTag = (field, value) => {
    setForm((f) => {
      const arr = f[field] || [];
      return { ...f, [field]: arr.includes(value) ? arr.filter((x) => x !== value) : [...arr, value] };
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.company.trim() || !form.email.trim()) return;
    setSaving(true);
    await onSave(form);
    setSaving(false);
  };

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={onClose}>
      <div
        className="bg-[#12121e] border border-[#2a2a4a] rounded-lg w-[520px] max-h-[85vh] overflow-y-auto p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="text-white font-semibold text-sm mb-4">Edit Client</h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Company + Email */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] uppercase text-gray-500 font-semibold block mb-1">Company Name *</label>
              <input className={inputCls} value={form.company} onChange={(e) => set("company", e.target.value)} />
            </div>
            <div>
              <label className="text-[10px] uppercase text-gray-500 font-semibold block mb-1">Email *</label>
              <input className={inputCls} type="email" value={form.email} onChange={(e) => set("email", e.target.value)} />
            </div>
          </div>

          {/* Optional contact person */}
          <div>
            <label className="text-[10px] uppercase text-gray-500 font-semibold block mb-1">Contact Name (optional)</label>
            <input className={inputCls} value={form.full_name} onChange={(e) => set("full_name", e.target.value)} placeholder="Optional" />
          </div>

          {/* Sectors */}
          <div>
            <label className="text-[10px] uppercase text-gray-500 font-semibold block mb-1.5">Sectors / Interests</label>
            <div className="flex flex-wrap gap-1.5">
              {ALLOWED_SECTORS.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleTag("interests", s)}
                  className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                    form.interests.includes(s)
                      ? "bg-[#38BDF8]/15 text-[#38BDF8] border-[#38BDF8]/40 font-semibold"
                      : "bg-[#0f0f1f] text-gray-500 border-[#2a2a4a] hover:border-gray-500"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Regions */}
          <div>
            <label className="text-[10px] uppercase text-gray-500 font-semibold block mb-1.5">Regions</label>
            <div className="flex flex-wrap gap-1.5">
              {ALLOWED_REGIONS.map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => toggleTag("regions", r)}
                  className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                    form.regions.includes(r)
                      ? "bg-[#38BDF8]/15 text-[#38BDF8] border-[#38BDF8]/40 font-semibold"
                      : "bg-[#0f0f1f] text-gray-500 border-[#2a2a4a] hover:border-gray-500"
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>

          {/* Active toggle */}
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(e) => set("is_active", e.target.checked)}
              className="accent-[#38BDF8]"
              id="edit-active"
            />
            <label htmlFor="edit-active" className="text-xs text-gray-400">Active</label>
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-2 border-t border-[#2a2a4a]">
            <button
              type="button"
              onClick={onClose}
              className="text-gray-400 hover:text-gray-200 text-sm px-3 py-1.5 rounded hover:bg-[#1a1a2e] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !form.company.trim() || !form.email.trim()}
              className="bg-[#38BDF8] hover:bg-[#FFD700] disabled:opacity-50 text-[#2E2E38] text-sm font-semibold px-4 py-1.5 rounded transition-colors"
            >
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body
  );
}

// ─── Single client row with expandable product panel ─────

function ClientRow({ client, onInventoryChange, onClientUpdate }) {
  const [expanded, setExpanded] = useState(false);
  const [inventory, setInventory] = useState(client.inventory || []);
  const [regions, setRegions] = useState(client.regions || []);
  const [editingIdx, setEditingIdx] = useState(null);
  const [addingProduct, setAddingProduct] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savingRegions, setSavingRegions] = useState(false);
  const [preview, setPreview] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [dropOver, setDropOver] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const dragIdx = useRef(null);
  const { addToast } = useToast();

  useEffect(() => {
    setInventory(client.inventory || []);
    setRegions(client.regions || []);
  }, [client.inventory, client.regions]);

  const handleEditSave = async (form) => {
    try {
      // Update main fields via PUT /recipients/{id}
      const res = await api.put(`/api/notifications/recipients/${client.id}`, {
        full_name: form.full_name || form.company,
        email: form.email,
        company: form.company || null,
        interests: form.interests,
        is_active: form.is_active,
      });
      // Update regions separately
      await api.put(`/api/notifications/recipients/${client.id}/regions`, { regions: form.regions });
      setRegions(form.regions);
      onClientUpdate(client.id, { ...res.data, regions: form.regions });
      setEditOpen(false);
      addToast("Client updated.", "success");
    } catch (err) {
      addToast(errorMessage(err, "Failed to update client."), "error");
    }
  };

  const addRegion = async (region) => {
    if (regions.includes(region)) return;
    const updated = [...regions, region];
    setSavingRegions(true);
    try {
      await api.put(`/api/notifications/recipients/${client.id}/regions`, { regions: updated });
      setRegions(updated);
    } catch (err) {
      addToast(errorMessage(err, "Failed to save regions."), "error");
    } finally {
      setSavingRegions(false);
    }
  };

  const removeRegion = async (region) => {
    const updated = regions.filter((r) => r !== region);
    setSavingRegions(true);
    try {
      await api.put(`/api/notifications/recipients/${client.id}/regions`, { regions: updated });
      setRegions(updated);
    } catch (err) {
      addToast(errorMessage(err, "Failed to save regions."), "error");
    } finally {
      setSavingRegions(false);
    }
  };

  const persist = async (newInventory) => {
    setSaving(true);
    try {
      await api.put(`/api/notifications/recipients/${client.id}/inventory`, {
        inventory: newInventory,
      });
      setInventory(newInventory);
      onInventoryChange(client.id, newInventory);
    } catch (err) {
      addToast(errorMessage(err, "Failed to save inventory."), "error");
    } finally {
      setSaving(false);
    }
  };

  const handleAdd = async (product) => {
    await persist([...inventory, product]);
    setAddingProduct(false);
  };

  const handleEdit = async (idx, product) => {
    await persist(inventory.map((p, i) => (i === idx ? product : p)));
    setEditingIdx(null);
  };

  const handleDelete = (idx) => {
    persist(inventory.filter((_, i) => i !== idx));
  };

  const handleExcelUpload = async (file) => {
    if (!file?.name.endsWith(".xlsx")) {
      addToast("Only .xlsx files are supported.", "error");
      return;
    }
    setUploading(true);
    const fd = new FormData();
    fd.append("file", file);
    try {
      const res = await api.post(
        `/api/notifications/recipients/${client.id}/preview-inventory`,
        fd,
        { headers: { "Content-Type": "multipart/form-data" } }
      );
      setPreview(res.data);
    } catch (err) {
      addToast(errorMessage(err, "Failed to parse file."), "error");
    } finally {
      setUploading(false);
    }
  };

  const handleConfirmExcel = async (finalInventory) => {
    setConfirming(true);
    try {
      await api.put(`/api/notifications/recipients/${client.id}/inventory`, {
        inventory: finalInventory,
      });
      setInventory(finalInventory);
      onInventoryChange(client.id, finalInventory);
      addToast("Inventory saved.", "success");
      setPreview(null);
    } catch (err) {
      addToast(errorMessage(err, "Failed to save inventory."), "error");
    } finally {
      setConfirming(false);
    }
  };

  const handleDragStart = (idx) => { dragIdx.current = idx; };
  const handleDragOver = (e, idx) => {
    e.preventDefault();
    if (dragIdx.current === null || dragIdx.current === idx) return;
    const reordered = [...inventory];
    const [moved] = reordered.splice(dragIdx.current, 1);
    reordered.splice(idx, 0, moved);
    dragIdx.current = idx;
    setInventory(reordered);
  };
  const handleDrop = () => {
    dragIdx.current = null;
    persist(inventory);
  };

  const vendors = [...new Set(inventory.map((p) => p.vendor).filter(Boolean))];

  return (
    <>
      <tr
        onClick={() => setExpanded((e) => !e)}
        onDragEnter={(e) => { e.preventDefault(); e.stopPropagation(); setDropOver(true); }}
        onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
        onDragLeave={(e) => { e.stopPropagation(); setDropOver(false); }}
        onDrop={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setDropOver(false);
          const file = e.dataTransfer.files?.[0];
          if (file) handleExcelUpload(file);
        }}
        className={`cursor-pointer transition-colors ${
          dropOver
            ? "bg-[#38BDF8]/10 border border-[#38BDF8]/40"
            : expanded ? "bg-[#1e1e3a]" : "hover:bg-[#161628]"
        }`}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <span
              className="text-gray-500 text-[10px] transition-transform duration-150 inline-block"
              style={{ transform: expanded ? "rotate(90deg)" : "rotate(0deg)" }}
            >
              ▶
            </span>
            <div>
              <div className="font-medium text-gray-200">{client.full_name}</div>
              <div className="text-xs text-gray-500">{client.email}</div>
            </div>
          </div>
        </td>
        <td className="px-4 py-3 text-gray-400 text-xs">{client.company || "—"}</td>
        <td className="px-4 py-3">
          <div className="flex flex-wrap gap-1">
            {vendors.map((v) => (
              <span key={v} className="text-[10px] px-1.5 py-0.5 rounded bg-[#2a2a4a] text-gray-300">
                {v}
              </span>
            ))}
            {vendors.length === 0 && <span className="text-gray-600 text-xs">—</span>}
          </div>
        </td>
        <td className="px-4 py-3">
          <span
            className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
              inventory.length > 0
                ? "text-green-400 border-green-800 bg-green-900/20"
                : "text-gray-600 border-gray-700"
            }`}
          >
            {inventory.length} products
          </span>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <span
              className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                client.is_active
                  ? "text-green-400 border-green-800"
                  : "text-gray-600 border-gray-700"
              }`}
            >
              {client.is_active ? "Active" : "Inactive"}
            </span>
            <button
              onClick={(e) => { e.stopPropagation(); setEditOpen(true); }}
              className="text-gray-500 hover:text-[#38BDF8] transition-colors text-sm"
              title="Edit client"
            >
              ✎
            </button>
          </div>
        </td>
      </tr>

      {expanded && (
        <tr>
          <td
            colSpan={5}
            className={`px-4 py-3 border-t border-[#1e1e3a] transition-colors ${dropOver ? "bg-[#38BDF8]/10" : "bg-[#0c0c1a]"}`}
            onDragEnter={(e) => { e.preventDefault(); e.stopPropagation(); setDropOver(true); }}
            onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
            onDragLeave={(e) => { e.stopPropagation(); setDropOver(false); }}
            onDrop={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setDropOver(false);
              const file = e.dataTransfer.files?.[0];
              if (file) handleExcelUpload(file);
            }}
          >
            {dropOver && (
              <div className="mb-3 p-3 border-2 border-dashed border-[#38BDF8]/50 rounded-lg text-center">
                <p className="text-[#38BDF8] text-sm font-medium">Drop Excel file here</p>
              </div>
            )}
            <div className="space-y-3">
              {/* Region Picker */}
              <div onClick={(e) => e.stopPropagation()}>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                    Regions
                  </span>
                  {savingRegions && <span className="text-[9px] text-gray-600 animate-pulse">saving...</span>}
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  {regions.map((r) => (
                    <span key={r} className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-[#2E2E38] text-[#38BDF8] font-semibold">
                      {r}
                      <button onClick={() => removeRegion(r)} className="text-[#38BDF8]/60 hover:text-red-400 ml-0.5 leading-none">&times;</button>
                    </span>
                  ))}
                  <select
                    value=""
                    onChange={(e) => { if (e.target.value) addRegion(e.target.value); }}
                    className="text-[10px] px-1.5 py-0.5 bg-[#0f0f23] border border-[#2a2a4a] rounded text-gray-400 focus:outline-none focus:border-[#38BDF8]/40"
                  >
                    <option value="">+ Add region</option>
                    {ALLOWED_REGIONS.filter((r) => !regions.includes(r)).map((r) => (
                      <option key={r} value={r}>{r}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Toolbar */}
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                  Product Inventory — {inventory.length} {inventory.length === 1 ? "entry" : "entries"}
                </span>
                <div className="flex items-center gap-2">
                  <label
                    onClick={(e) => e.stopPropagation()}
                    className={`text-[10px] px-2.5 py-1 rounded border border-[#2a2a4a] text-gray-400 hover:text-gray-200 hover:border-[#3a3a5a] hover:bg-[#1a1a2e] transition-colors cursor-pointer ${uploading ? "opacity-50 pointer-events-none" : ""}`}
                  >
                    {uploading ? "Parsing…" : "Upload Excel"}
                    <input
                      type="file"
                      accept=".xlsx"
                      className="hidden"
                      onChange={(e) => {
                        handleExcelUpload(e.target.files?.[0]);
                        e.target.value = "";
                      }}
                    />
                  </label>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setAddingProduct(true);
                      setEditingIdx(null);
                    }}
                    className="text-[10px] px-2.5 py-1 rounded border border-[#38BDF8]/30 text-[#38BDF8] bg-[#38BDF8]/5 hover:bg-[#38BDF8]/10 transition-colors"
                  >
                    + Add Product
                  </button>
                </div>
              </div>

              {/* Products table */}
              <table
                className="w-full text-xs"
                onClick={(e) => e.stopPropagation()}
              >
                <thead>
                  <tr className="text-gray-500 border-b border-[#1e1e3a]">
                    <th className="px-2 py-1 w-4" />
                    <th className="text-left px-2 py-1">Vendor</th>
                    <th className="text-left px-2 py-1">Product</th>
                    <th className="text-left px-2 py-1">Family</th>
                    <th className="text-left px-2 py-1">Version</th>
                    <th className="px-2 py-1 w-20" />
                  </tr>
                </thead>
                <tbody>
                  {inventory.length === 0 && !addingProduct && (
                    <tr>
                      <td colSpan={5} className="px-2 py-4 text-center text-gray-600 italic">
                        No products yet. Add manually or upload an Excel file.
                      </td>
                    </tr>
                  )}

                  {inventory.map((item, idx) =>
                    editingIdx === idx ? (
                      <ProductForm
                        key={idx}
                        initial={item}
                        onSave={(updated) => handleEdit(idx, updated)}
                        onCancel={() => setEditingIdx(null)}
                      />
                    ) : (
                      <tr
                        key={idx}
                        draggable
                        onDragStart={() => handleDragStart(idx)}
                        onDragOver={(e) => handleDragOver(e, idx)}
                        onDrop={handleDrop}
                        className="text-gray-300 border-t border-[#1a1a2e] hover:bg-[#121220] cursor-grab active:cursor-grabbing"
                      >
                        <td className="px-2 py-1.5 text-gray-600 select-none">⠿</td>
                        <td className="px-2 py-1.5">{item.vendor}</td>
                        <td className="px-2 py-1.5 text-gray-400">{item.product_raw}</td>
                        <td className="px-2 py-1.5 text-gray-500">{item.product_family || "—"}</td>
                        <td className="px-2 py-1.5 font-mono">{item.version || "—"}</td>
                        <td className="px-2 py-1.5">
                          <div className="flex items-center gap-2 justify-end">
                            <button
                              onClick={() => {
                                setEditingIdx(idx);
                                setAddingProduct(false);
                              }}
                              className="text-gray-500 hover:text-[#38BDF8] transition-colors text-sm"
                              title="Edit"
                            >
                              ✎
                            </button>
                            <button
                              onClick={() => handleDelete(idx)}
                              disabled={saving}
                              className="text-gray-600 hover:text-red-400 transition-colors text-base leading-none"
                              title="Delete"
                            >
                              ×
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  )}

                  {addingProduct && (
                    <ProductForm
                      onSave={handleAdd}
                      onCancel={() => setAddingProduct(false)}
                    />
                  )}
                </tbody>
              </table>

              {saving && (
                <p className="text-[10px] text-gray-500 animate-pulse">Saving…</p>
              )}
            </div>
          </td>
        </tr>
      )}

      {preview && createPortal(
        <InventoryPreviewModal
          preview={preview}
          currentInventory={inventory}
          clientName={client.full_name}
          onConfirm={handleConfirmExcel}
          onClose={() => setPreview(null)}
          confirming={confirming}
        />,
        document.body
      )}

      {editOpen && (
        <EditClientModal
          client={client}
          onSave={handleEditSave}
          onClose={() => setEditOpen(false)}
        />
      )}
    </>
  );
}

// ─── Main Page ────────────────────────────────────────────

export default function ClientsPage() {
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [importPreview, setImportPreview] = useState(null);
  const [importUploading, setImportUploading] = useState(false);
  const [importConfirming, setImportConfirming] = useState(false);
  const [generalDropOver, setGeneralDropOver] = useState(false);
  const [generalUploading, setGeneralUploading] = useState(false);
  const { addToast } = useToast();

  const fetchClients = useCallback(async () => {
    try {
      const res = await api.get("/api/notifications/clients");
      setClients(res.data || []);
    } catch {
      addToast("Failed to load clients.", "error");
    } finally {
      setLoading(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchClients();
  }, [fetchClients]);

  const handleInventoryChange = (clientId, newInventory) => {
    setClients((prev) =>
      prev.map((c) => {
        if (c.id !== clientId) return c;
        const vendors = [...new Set(newInventory.map((p) => p.vendor).filter(Boolean))];
        return { ...c, inventory: newInventory, vendors };
      })
    );
  };

  const handleClientUpdate = (clientId, updated) => {
    setClients((prev) =>
      prev.map((c) => (c.id === clientId ? { ...c, ...updated } : c))
    );
  };

  const handleImportUpload = async (file) => {
    if (!file?.name.endsWith(".xlsx")) {
      addToast("Only .xlsx files are supported.", "error");
      return;
    }
    setImportUploading(true);
    const fd = new FormData();
    fd.append("file", file);
    try {
      const res = await api.post("/api/notifications/recipients/import-preview", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setImportPreview(res.data);
    } catch (err) {
      addToast(errorMessage(err, "Failed to parse file."), "error");
    } finally {
      setImportUploading(false);
    }
  };

  // General inventory drop: identifies the client by the Company/Email header in
  // the sheet, creates the client if it doesn't exist, and merges the inventory.
  const handleGeneralInventoryDrop = async (file) => {
    if (!file?.name.endsWith(".xlsx")) {
      addToast("Only .xlsx files are supported.", "error");
      return;
    }
    setGeneralUploading(true);
    const fd = new FormData();
    fd.append("file", file);
    try {
      const res = await api.post("/api/notifications/recipients/import-inventory", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      const { created, client, products_added, total_products } = res.data;
      addToast(
        created
          ? `Created client "${client.company}" with ${total_products} product(s).`
          : `Updated "${client.company}": +${products_added} product(s) (${total_products} total).`,
        "success"
      );
      fetchClients();
    } catch (err) {
      addToast(errorMessage(err, "Could not import inventory."), "error");
    } finally {
      setGeneralUploading(false);
    }
  };

  const handleImportConfirm = async (newClients, applyUpdates) => {
    setImportConfirming(true);
    try {
      const res = await api.post("/api/notifications/recipients/import-confirm", {
        new_clients: newClients,
        apply_updates: applyUpdates,
      });
      addToast(`Imported ${res.data.created} new, updated ${res.data.updated} existing.`, "success");
      setImportPreview(null);
      fetchClients();
    } catch (err) {
      addToast(errorMessage(err, "Import failed."), "error");
    } finally {
      setImportConfirming(false);
    }
  };

  const filtered = clients.filter((c) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      c.full_name.toLowerCase().includes(q) ||
      c.email.toLowerCase().includes(q) ||
      (c.company && c.company.toLowerCase().includes(q))
    );
  });

  if (loading) return <div className="text-gray-400 text-sm">Loading…</div>;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Client Management</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Manage client product inventories for CVE matching. To add or remove clients, use the Admin panel.
          </p>
        </div>
        <label
          className={`px-3 py-1.5 text-xs rounded bg-[#38BDF8]/10 border border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20 transition-colors cursor-pointer ${importUploading ? "opacity-50 pointer-events-none" : ""}`}
        >
          {importUploading ? "Parsing…" : "Import Client Inventory"}
          <input
            type="file"
            accept=".xlsx"
            className="hidden"
            onChange={(e) => {
              handleImportUpload(e.target.files?.[0]);
              e.target.value = "";
            }}
          />
        </label>
      </div>

      {/* Search */}
      <div className="flex items-center gap-3">
        <input
          className="bg-[#12121e] border border-[#2a2a4a] rounded px-3 py-1.5 text-sm text-gray-200 outline-none focus:border-[#38BDF8]/40 w-64 placeholder-gray-600"
          placeholder="Search client, company…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <span className="text-xs text-gray-500">
          {clients.length} client{clients.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* General inventory drop zone — create or update a client from a sheet */}
      <label
        onDragEnter={(e) => { e.preventDefault(); e.stopPropagation(); setGeneralDropOver(true); }}
        onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
        onDragLeave={(e) => { e.stopPropagation(); setGeneralDropOver(false); }}
        onDrop={(e) => {
          e.preventDefault(); e.stopPropagation(); setGeneralDropOver(false);
          const f = e.dataTransfer.files?.[0];
          if (f) handleGeneralInventoryDrop(f);
        }}
        className={`block border-2 border-dashed rounded-lg px-4 py-5 text-center cursor-pointer transition-colors ${
          generalDropOver ? "border-[#38BDF8] bg-[#38BDF8]/10" : "border-[#2a2a4a] bg-[#0c0c1a] hover:border-[#38BDF8]/40"
        } ${generalUploading ? "opacity-60 pointer-events-none" : ""}`}
      >
        <input
          type="file"
          accept=".xlsx"
          className="hidden"
          onChange={(e) => { handleGeneralInventoryDrop(e.target.files?.[0]); e.target.value = ""; }}
        />
        <p className="text-sm text-gray-300 font-medium">
          {generalUploading ? "Importing…" : "Drop a client inventory sheet here (or click) to create / update a client"}
        </p>
        <p className="text-[11px] text-gray-500 mt-1">
          The sheet must include a <span className="text-gray-300">Company:</span> and{" "}
          <span className="text-gray-300">Email:</span> header above the Vendor / Product / Version table.
          A new client is created only if it does not already exist.
        </p>
      </label>

      {/* Table */}
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2a4a]">
              <th className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                Client
              </th>
              <th className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                Company
              </th>
              <th className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                Vendors
              </th>
              <th className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                Products
              </th>
              <th className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1a1a2e]">
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-10 text-center text-gray-600 text-sm italic">
                  {clients.length === 0
                    ? "No clients yet. Add a client using the button above."
                    : "No clients match your search."}
                </td>
              </tr>
            )}
            {filtered.map((client) => (
              <ClientRow
                key={client.id}
                client={client}
                onInventoryChange={handleInventoryChange}
                onClientUpdate={handleClientUpdate}
              />
            ))}
          </tbody>
        </table>
      </div>

      <ImportPreviewModal
        preview={importPreview}
        onConfirm={handleImportConfirm}
        onClose={() => setImportPreview(null)}
        confirming={importConfirming}
      />
    </div>
  );
}
