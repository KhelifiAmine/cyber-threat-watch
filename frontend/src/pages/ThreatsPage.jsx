import { useState, useEffect, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import api from "../api/axios";
import SeverityBadge from "../components/ui/SeverityBadge";
import Pagination from "../components/ui/Pagination";
import SearchBar from "../components/ui/SearchBar";
import FilterSelect from "../components/ui/FilterSelect";
import { errorMessage } from "../api/errors";
import { useToast } from "../context/ToastContext";
import ConfirmModal from "../components/ui/ConfirmModal";
import useCascadingFilters from "../hooks/useCascadingFilters";
import AdvisoryEditor from "../components/review/AdvisoryEditor";
import TicketCard from "../components/ui/TicketCard";

function normalizeRemediationSteps(steps = []) {
  return steps.map((s, i) => {
    if (typeof s === "string") return { label: String(i + 1), action: s, reference_label: "", reference_url: "" };
    return { label: s.label ?? String(i + 1), action: s.action ?? "", reference_label: s.reference_label ?? "", reference_url: s.reference_url ?? "" };
  });
}

function threatToAdvisory(threat) {
  const enrichment = threat.enrichment_data || {};
  const d = threat.created_at ? new Date(threat.created_at) : new Date();
  const advisoryId = `${String(d.getFullYear()).slice(2)}${String(d.getMonth()+1).padStart(2,"0")}${String(d.getDate()).padStart(2,"0")}`;
  return {
    kind: "threat",
    cveId: null,
    threatId: threat.id,
    proposalId: null,
    proposalKind: null,
    origin: null,
    flagNote: null,
    advisoryId,
    title: threat.title || "",
    summary: threat.description || "",
    description: threat.description || "",
    publishedAt: threat.published_at ? new Date(threat.published_at).toLocaleDateString("en-GB", { day: "2-digit", month: "long", year: "numeric" }) : "",
    cveIds: "",
    cvssScore: null,
    cvssSeverity: "",
    cvssVector: "",
    vendor: "",
    patchAvailable: "unknown",
    patchUrl: "",
    exploitAvailable: "unknown",
    riskScore: threat.risk_score ?? null,
    severity: (threat.severity || "").toLowerCase(),
    threatType: threat.threat_type || "",
    ttpCodes: threat.ttp_codes || "",
    regions: threat.regions || "",
    sourceUrl: threat.source_url || "",
    enrichedProducts: enrichment.affected_products || [],
    clientMatches: enrichment.client_matches || [],
    impactPoints: enrichment.impact_points || [],
    remediationSteps: normalizeRemediationSteps(enrichment.remediation_steps),
    tempMitigation: enrichment.temp_mitigation || [],
    additionalResources: threat.source_url ? [{ name: "Source", url: threat.source_url }] : [],
    advisory_sent_at: threat.advisory_sent_at || null,
    advisory_sent_by: threat.advisory_sent_by || null,
  };
}

const severityOptions = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];


const sortOptions = [
  { value: "created_at", label: "Newest" },
  { value: "oldest", label: "Oldest" },
  { value: "risk_desc", label: "Highest Risk" },
  { value: "severity", label: "Severity" },
];

const reviewStatusOptions = [
  { value: "none", label: "Never reviewed" },
  { value: "approved", label: "Approved" },
  { value: "rejected", label: "Rejected" },
];

function ReviewBadge({ status }) {
  if (status !== "APPROVED") return null;
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded border bg-green-900/30 text-green-400 border-green-700/50">
      APPROVED
    </span>
  );
}

function EditedBadge({ editedBy }) {
  if (!editedBy) return null;
  return (
    <span
      title={`Edited by ${editedBy}`}
      className="text-[9px] px-1.5 py-0.5 rounded border bg-blue-900/30 text-blue-400 border-blue-700/50 cursor-default"
    >
      EDITED
    </span>
  );
}

function SentBadge({ sentAt, sentBy }) {
  if (!sentAt) return null;
  const date = new Date(sentAt).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
  return (
    <span
      title={`Sent by ${sentBy || "unknown"} on ${date}`}
      className="text-[9px] px-1.5 py-0.5 rounded border bg-green-900/30 text-green-400 border-green-700/50 cursor-default"
    >
      SENT
    </span>
  );
}


export default function ThreatsPage() {
  const { user } = useAuth();
  const { addToast } = useToast();
  const [searchParams] = useSearchParams();
  const [threats, setThreats] = useState([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(0);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [threatSource, setThreatSource] = useState("");
  const [threatSourceOptions, setThreatSourceOptions] = useState([]);
  const [severity, setSeverity] = useState("");
  const [region, setRegion] = useState("");
  const [sortBy, setSortBy] = useState("created_at");
  const [reviewStatus, setReviewStatus] = useState("");
  const [sentFilter, setSentFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [flagging, setFlagging] = useState(false);
  const [flagModal, setFlagModal] = useState(null);   // threat id to flag
  const [deleteConfirm, setDeleteConfirm] = useState(null); // threat id to delete

  const canEdit = user?.role === "admin" || user?.role === "analyst";
  const isClient = user?.role === "client";
  const [openAdvisory, setOpenAdvisory] = useState(null);


  // Cascading filter options
  const { options: cascadingOptions } = useCascadingFilters(
    "/api/threats/filter-options",
    ["source", "severity", "region", "sent"],
    { source: threatSource, severity, region, sent: sentFilter || undefined }
  );

  useEffect(() => {
    if (cascadingOptions.sources?.length > 0) {
      setThreatSourceOptions(cascadingOptions.sources.map((s) => ({
        value: s.value,
        label: `${s.value} (${s.count})`,
      })));
    } else {
      api.get("/api/threats/sources").then((res) => {
        setThreatSourceOptions((res.data || []).map((s) => ({ value: s, label: s })));
      }).catch(() => {});
    }
  }, [cascadingOptions.sources]);

  const handleAdvisorySave = async (form) => {
    const enrichment_data = {
      affected_products: form.enrichedProducts || [],
      impact_points: form.impactPoints || [],
      remediation_steps: form.remediationSteps || [],
      temp_mitigation: form.tempMitigation || [],
    };
    const res = await api.patch(`/api/threats/${form.threatId}`, {
      title: form.title || null,
      description: form.description || null,
      severity: form.severity || null,
      threat_type: form.threatType || null,
      ttp_codes: form.ttpCodes || null,
      risk_score: form.riskScore ?? null,
      regions: form.regions || null,
      source_url: form.sourceUrl || null,
      enrichment_data,
    });
    setSelected(res.data);
  };

  const handleAdvisorySend = async (form, recipientIds) => {
    const res = await api.post("/api/advisory/send", {
      kind: "threat",
      record_id: String(form.threatId),
      recipient_ids: recipientIds?.length ? recipientIds : null,
    });
    return res.data;
  };


  const handleFlag = async (threatId, note) => {
    setFlagging(true);
    try {
      await api.post("/api/proposals/flag", { threat_id: threatId, note: note || null });
      addToast("Flagged for review. This threat will reappear once the ticket is closed.", "success");
      setSelected(null);
      fetchThreats();
    } catch (e) {
      addToast(errorMessage(e, "Failed to flag."), "error");
    } finally {
      setFlagging(false);
      setFlagModal(null);
    }
  };

const fetchThreats = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, per_page: 20, sort_by: sortBy };
      if (search) params.search = search;
      if (threatSource) params.source = threatSource;
      if (severity) params.severity = severity;
      if (region) params.region = region;
      if (reviewStatus) params.review_status = reviewStatus;
      if (sentFilter) params.sent = sentFilter === "true";
      const res = await api.get("/api/threats/", { params });
      setThreats(res.data.items || []);
      setTotal(res.data.total || 0);
      setPages(res.data.pages || 0);
    } catch {
      setThreats([]);
    } finally {
      setLoading(false);
    }
  }, [page, search, threatSource, severity, region, sortBy, reviewStatus, sentFilter]);

  useEffect(() => { fetchThreats(); }, [fetchThreats]);

  const handleSearch = (val) => { setSearch(val); setPage(1); };

  const handleDelete = async (id) => {
    try {
      await api.delete(`/api/threats/${id}`);
      setSelected(null);
      fetchThreats();
    } catch { /* ignore */ }
    setDeleteConfirm(null);
  };

  if (selected) {
    return (
      <div className="space-y-4">
        {flagModal && (
          <ConfirmModal
            message="Flag this threat for review?"
            confirmLabel="Flag"
            withInput
            inputLabel="Note for analyst (optional)"
            inputPlaceholder="Add context about why you're flagging this..."
            onConfirm={(note) => handleFlag(flagModal, note)}
            onCancel={() => setFlagModal(null)}
          />
        )}
        {deleteConfirm && (
          <ConfirmModal
            message="Delete this threat? This cannot be undone."
            confirmLabel="Delete"
            danger
            onConfirm={() => handleDelete(deleteConfirm)}
            onCancel={() => setDeleteConfirm(null)}
          />
        )}
        <button onClick={() => setSelected(null)} className="text-sm text-gray-400 hover:text-white">&larr; Back to list</button>
        <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-6 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <ReviewBadge status={selected.review_status} />
                <EditedBadge editedBy={selected.edited_by} />
                <SentBadge sentAt={selected.advisory_sent_at} sentBy={selected.advisory_sent_by} />
              </div>
              <h1 className="text-lg font-bold text-white">{selected.title}</h1>
              {selected.edited_by && (
                <p className="text-xs text-gray-600 mt-0.5">Last edited by {selected.edited_by}</p>
              )}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge value={selected.severity} />
              {canEdit && (
                <>
                  <button
                    onClick={() => setFlagModal(selected.id)}
                    disabled={flagging}
                    className="px-3 py-1 text-xs rounded bg-[#38BDF8]/10 border border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20 disabled:opacity-50"
                  >
                    Flag for review
                  </button>
                  <button
                    onClick={() => setOpenAdvisory(threatToAdvisory(selected))}
                    className="px-3 py-1 text-xs rounded bg-[#38BDF8] text-[#2E2E38] font-semibold hover:bg-[#FFD700]"
                  >
                    Open in Advisory Editor
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div><span className="text-gray-500">Risk Score</span><p className="text-white font-bold">{selected.risk_score}</p></div>
            <div><span className="text-gray-500">Source</span><p className="text-white">{selected.source}</p></div>
            <div><span className="text-gray-500">Type</span><p className="text-white">{selected.threat_type || "—"}</p></div>
            <div><span className="text-gray-500">Published</span><p className="text-white">{selected.published_at ? new Date(selected.published_at).toLocaleDateString() : "—"}</p></div>
          </div>

          {selected.ttp_codes && (
            <div>
              <span className="text-gray-500 text-sm">TTP Codes</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {selected.ttp_codes.split(",").map((t) => (
                  <span key={t} className="text-[11px] px-2 py-0.5 rounded bg-[#0f0f23] border border-[#2a2a4a] text-[#00d4ff] font-mono">{t.trim()}</span>
                ))}
              </div>
            </div>
          )}

          {/* Enriched Products */}
          {selected.enrichment_data?.affected_products?.length > 0 && (
            <div>
              <span className="text-gray-500 text-sm">Affected Products</span>
              <div className="mt-1 border border-[#2a2a4a] rounded overflow-hidden">
                <table className="w-full text-xs">
                  <thead><tr className="bg-[#0f0f23] text-gray-500 uppercase">
                    <th className="text-left px-3 py-1.5">Product</th>
                    <th className="text-left px-3 py-1.5">Versions</th>
                    <th className="text-left px-3 py-1.5">Notes</th>
                  </tr></thead>
                  <tbody>{selected.enrichment_data.affected_products.map((p, i) => (
                    <tr key={i} className="border-t border-[#1e1e3a]">
                      <td className="px-3 py-1.5 text-white font-medium">{p.name || "—"}</td>
                      <td className="px-3 py-1.5 text-gray-400 font-mono">{p.versions || "—"}</td>
                      <td className="px-3 py-1.5 text-gray-500">{p.notes || "—"}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            </div>
          )}

          {/* Executive Summary */}
          {selected.enrichment_data?.summary && (
            <div>
              <span className="text-gray-500 text-sm">Executive Summary</span>
              <p className="text-gray-300 text-sm mt-1 leading-relaxed whitespace-pre-wrap">{selected.enrichment_data.summary}</p>
            </div>
          )}

          {/* Impact Points */}
          {selected.enrichment_data?.impact_points?.length > 0 && (
            <div>
              <span className="text-gray-500 text-sm">Impact</span>
              <ul className="mt-1 space-y-0.5">
                {selected.enrichment_data.impact_points.map((p, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                    <span className="text-red-400 mt-0.5 shrink-0">•</span>
                    <span>{p}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Remediation Steps */}
          {selected.enrichment_data?.remediation_steps?.length > 0 && (
            <div>
              <span className="text-gray-500 text-sm">Remediation</span>
              <ul className="mt-1 space-y-0.5">
                {selected.enrichment_data.remediation_steps.map((s, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                    <span className="text-green-400 font-mono text-xs mt-0.5 shrink-0">{i + 1}.</span>
                    <span>{typeof s === "string" ? s : s.action || s}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Temporary Mitigations */}
          {selected.enrichment_data?.temp_mitigation?.length > 0 && (
            <div>
              <span className="text-gray-500 text-sm">Temporary Mitigation</span>
              <ul className="mt-1 space-y-0.5">
                {selected.enrichment_data.temp_mitigation.map((m, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                    <span className="text-yellow-400 mt-0.5 shrink-0">•</span>
                    <span>{m}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Affected Regions */}
          {selected.enrichment_data?.affected_regions?.length > 0 && (
            <div>
              <span className="text-gray-500 text-sm">Affected Regions</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {selected.enrichment_data.affected_regions.map((r, i) => (
                  <span key={i} className="text-[11px] px-2 py-0.5 rounded bg-[#0f0f23] border border-[#2a2a4a] text-blue-400">{r}</span>
                ))}
              </div>
            </div>
          )}

          <div>
            <span className="text-gray-500 text-sm">Description</span>
            <p className="text-gray-300 text-sm mt-1 leading-relaxed whitespace-pre-wrap">{selected.description}</p>
          </div>

          {selected.source_url && (
            <a href={selected.source_url} target="_blank" rel="noopener noreferrer" className="text-[#00d4ff] text-sm hover:underline">View Source &rarr;</a>
          )}

          {user?.role === "admin" && (
            <div className="flex gap-2 pt-2 border-t border-[#2a2a4a]">
              <button onClick={() => setDeleteConfirm(selected.id)} className="px-3 py-1.5 text-xs rounded border border-red-800 text-red-400 hover:bg-red-900/30">Delete</button>
            </div>
          )}
        </div>
        {openAdvisory && (
          <AdvisoryEditor
            advisory={openAdvisory}
            onSave={handleAdvisorySave}
            onApprove={() => {}}
            onClose={() => setOpenAdvisory(null)}
            onSend={handleAdvisorySend}
            onDone={() => { setOpenAdvisory(null); setSelected(null); fetchThreats(); }}
          />
        )}
      </div>
    );
  }

  // CLIENT ticket view
  if (isClient) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-bold text-white">Threat Intelligence</h1>
        <SearchBar onSearch={handleSearch} placeholder="Search threats..." initialValue={search} />
        {loading ? (
          <p className="text-gray-600 text-sm py-8 text-center">Loading...</p>
        ) : threats.length === 0 ? (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-8 text-center text-gray-600 text-sm">
            No threats matching your profile.
          </div>
        ) : (
          <div className="space-y-3">
            {threats.map((t) => (
              <TicketCard key={t.id} item={t} type="threat" onClick={() => setSelected(t)} />
            ))}
          </div>
        )}
        <Pagination page={page} pages={pages} onPageChange={setPage} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Threats</h1>
        <span className="text-gray-500 text-sm">{total} total</span>
      </div>

      <div className="flex flex-wrap items-end gap-4">
        <div className="flex-1 min-w-[200px]">
          <SearchBar onSearch={handleSearch} placeholder="Search by title, description, type, region..." initialValue={search} />
        </div>
        <FilterSelect label="Source" value={threatSource} onChange={(v) => { setThreatSource(v); setPage(1); }} options={threatSourceOptions} />
        <FilterSelect label="Severity" value={severity} onChange={(v) => { setSeverity(v); setPage(1); }} options={
          cascadingOptions.severities?.length > 0
            ? cascadingOptions.severities.map((s) => ({ value: s.value, label: `${s.value} (${s.count})` }))
            : severityOptions
        } />
        <FilterSelect label="Region" value={region} onChange={(v) => { setRegion(v); setPage(1); }} options={
          cascadingOptions.regions?.length > 0
            ? cascadingOptions.regions.map((r) => ({ value: r.value, label: `${r.value} (${r.count})` }))
            : [
                { value: "Global", label: "Global" },
                { value: "MENA", label: "MENA" },
                { value: "Europe", label: "Europe" },
                { value: "Asia", label: "Asia" },
                { value: "Americas", label: "Americas" },
              ]
        } />
        <FilterSelect label="Sent" value={sentFilter} onChange={(v) => { setSentFilter(v); setPage(1); }} options={[
          { value: "true", label: "Sent" },
          { value: "false", label: "Not Sent" },
        ]} />
        <FilterSelect label="Reviewed" value={reviewStatus} onChange={(v) => { setReviewStatus(v); setPage(1); }} options={reviewStatusOptions} />
        <FilterSelect label="Sort" value={sortBy} onChange={(v) => { setSortBy(v); setPage(1); }} options={sortOptions} />
      </div>

      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2a4a] text-gray-500 text-xs uppercase">
              <th className="text-left px-4 py-3 font-medium">Title</th>
              <th className="text-left px-4 py-3 font-medium w-24">Severity</th>
              <th className="text-left px-4 py-3 font-medium w-20">Risk</th>
              <th className="text-left px-4 py-3 font-medium w-28">Source</th>
              <th className="text-left px-4 py-3 font-medium w-28">Date</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-600">Loading...</td></tr>
            ) : threats.length === 0 ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-600">No threats found.</td></tr>
            ) : threats.map((t) => (
              <tr
                key={t.id}
                onClick={() => setSelected(t)}
                className="border-b border-[#1e1e3a] hover:bg-[#1a1a2e] cursor-pointer transition-colors"
              >
                <td className="px-4 py-3 text-gray-200 max-w-[300px]">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <ReviewBadge status={t.review_status} />
                    <EditedBadge editedBy={t.edited_by} />
                    <SentBadge sentAt={t.advisory_sent_at} sentBy={t.advisory_sent_by} />
                    <span className="truncate">{t.title}</span>
                  </div>
                </td>
                <td className="px-4 py-3"><SeverityBadge value={t.severity} /></td>
                <td className="px-4 py-3 text-white font-mono font-bold">{t.risk_score}</td>
                <td className="px-4 py-3 text-gray-400 truncate">{t.source}</td>
                <td className="px-4 py-3 text-gray-500 text-xs">{new Date(t.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Pagination page={page} pages={pages} onPageChange={setPage} />
    </div>
  );
}
