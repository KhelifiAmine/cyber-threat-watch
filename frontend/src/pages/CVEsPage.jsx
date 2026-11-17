import { useState, useEffect, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import api from "../api/axios";
import { useAuth } from "../context/AuthContext";
import SeverityBadge from "../components/ui/SeverityBadge";
import Pagination from "../components/ui/Pagination";
import SearchBar from "../components/ui/SearchBar";
import FilterSelect from "../components/ui/FilterSelect";
import TicketCard from "../components/ui/TicketCard";
import { errorMessage } from "../api/errors";
import { useToast } from "../context/ToastContext";
import ConfirmModal from "../components/ui/ConfirmModal";
import AdvisoryEditor from "../components/review/AdvisoryEditor";
import useCascadingFilters from "../hooks/useCascadingFilters";

function normalizeRemediationSteps(steps = []) {
  return steps.map((s, i) => {
    if (typeof s === "string") return { label: String(i + 1), action: s, reference_label: "", reference_url: "" };
    return { label: s.label ?? String(i + 1), action: s.action ?? "", reference_label: s.reference_label ?? "", reference_url: s.reference_url ?? "" };
  });
}

function cveToAdvisory(cve) {
  const enrichment = cve.enrichment_data || {};
  const d = cve.published_at ? new Date(cve.published_at) : new Date();
  const advisoryId = `${String(d.getFullYear()).slice(2)}${String(d.getMonth()+1).padStart(2,"0")}${String(d.getDate()).padStart(2,"0")}`;
  const affectedRaw = enrichment.affected_products?.length
    ? enrichment.affected_products
    : cve.affected_products
      ? [{ name: cve.affected_products, versions: "", notes: "" }]
      : [];
  return {
    kind: "cve",
    cveId: cve.cve_id,
    threatId: null,
    proposalId: null,
    proposalKind: null,
    origin: null,
    flagNote: null,
    advisoryId,
    title: cve.title || cve.cve_id || "",
    summary: cve.enrichment_data?.summary || cve.description || "",
    description: cve.description || "",
    publishedAt: cve.published_at ? new Date(cve.published_at).toLocaleDateString("en-GB", { day: "2-digit", month: "long", year: "numeric" }) : "",
    cveIds: cve.cve_id || "",
    cvssScore: cve.cvss_base_score ?? null,
    cvssSeverity: cve.cvss_severity || "",
    cvssVector: cve.cvss_vector || "",
    vendor: cve.vendor || "",
    patchAvailable: cve.patch_available || "unknown",
    patchUrl: cve.patch_url || "",
    exploitAvailable: cve.exploit_available || "unknown",
    riskScore: null,
    severity: (cve.cvss_severity || "").toLowerCase(),
    threatType: "",
    ttpCodes: "",
    regions: "",
    sourceUrl: cve.source_url || "",
    enrichedProducts: affectedRaw,
    clientMatches: enrichment.client_matches || [],
    impactPoints: enrichment.impact_points || [],
    remediationSteps: normalizeRemediationSteps(enrichment.remediation_steps),
    tempMitigation: enrichment.temp_mitigation || [],
    additionalResources: [
      ...(cve.source_url ? [{ name: "Source", url: cve.source_url }] : []),
      ...(cve.patch_url ? [{ name: "Patch", url: cve.patch_url }] : []),
    ],
    advisory_sent_at: cve.advisory_sent_at || null,
    advisory_sent_by: cve.advisory_sent_by || null,
  };
}

const severityOptions = [
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH", label: "High" },
  { value: "MEDIUM", label: "Medium" },
  { value: "LOW", label: "Low" },
];

const exploitOptions = [
  { value: "yes", label: "Yes" },
  { value: "no", label: "No" },
  { value: "unknown", label: "Unknown" },
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

function CvssBar({ score }) {
  if (score == null) return <span className="text-gray-600">—</span>;
  const pct = (score / 10) * 100;
  const color = score >= 9 ? "bg-red-500" : score >= 7 ? "bg-orange-500" : score >= 4 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-2 bg-[#0f0f23] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-white font-mono text-xs font-bold">{score}</span>
    </div>
  );
}


export default function CVEsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { addToast } = useToast();
  const { user } = useAuth();
  const isClient = user?.role === "client";
  const canEdit = user?.role === "admin" || user?.role === "analyst";
  const [cves, setCves] = useState([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(0);
  const [search, setSearch] = useState(() => searchParams.get("search") || "");
  const [cveSource, setCveSource] = useState("");
  const [cveSourceOptions, setCveSourceOptions] = useState([]);
  const [severity, setSeverity] = useState(() => (searchParams.get("severity") || "").toUpperCase());
  const [exploit, setExploit] = useState("");
  const [reviewStatus, setReviewStatus] = useState("");
  const [sentFilter, setSentFilter] = useState(() => searchParams.get("sent") || "");
  const [minCvss, setMinCvss] = useState(() => searchParams.get("min_cvss") || "");
  const [sortBy, setSortBy] = useState("newest");
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [flagging, setFlagging] = useState(false);
  const [flagModal, setFlagModal] = useState(null); // cve_id to flag
  const [openAdvisory, setOpenAdvisory] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);

  const perPage = 20;

  // Cascading filter options — options narrow based on current selections
  const { options: cascadingOptions } = useCascadingFilters(
    "/api/cves/filter-options",
    ["source", "severity", "exploit_available", "sent", "review_status"],
    { source: cveSource, severity, exploit_available: exploit, sent: sentFilter || undefined }
  );

  // Build source options from cascading data (with counts)
  useEffect(() => {
    if (cascadingOptions.sources?.length > 0) {
      setCveSourceOptions(cascadingOptions.sources.map((s) => ({
        value: s.value,
        label: `${s.value} (${s.count})`,
      })));
    } else {
      // Fallback: fetch all sources
      api.get("/api/cves/sources").then((res) => {
        setCveSourceOptions((res.data || []).map((s) => ({ value: s, label: s })));
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
    const res = await api.patch(`/api/cves/${encodeURIComponent(form.cveId)}`, {
      title: form.title || null,
      description: form.description || null,
      cvss_base_score: form.cvssScore ?? null,
      cvss_severity: form.cvssSeverity || null,
      cvss_vector: form.cvssVector || null,
      vendor: form.vendor || null,
      patch_available: form.patchAvailable || null,
      patch_url: form.patchUrl || null,
      exploit_available: form.exploitAvailable || null,
      source_url: form.sourceUrl || null,
      enrichment_data,
    });
    setSelected(res.data);
  };

  const handleAdvisorySend = async (form, recipientIds) => {
    const res = await api.post("/api/advisory/send", {
      kind: "cve",
      record_id: form.cveId,
      recipient_ids: recipientIds?.length ? recipientIds : null,
    });
    return res.data;
  };

  const handleFlag = async (cveId, note) => {
    setFlagging(true);
    try {
      await api.post("/api/proposals/flag", { cve_id: cveId, note: note || null });
      addToast("Flagged for review. This CVE will reappear once the ticket is closed.", "success");
      clearSelected();
      fetchCves();
    } catch (e) {
      addToast(errorMessage(e, "Failed to flag."), "error");
    } finally {
      setFlagging(false);
      setFlagModal(null);
    }
  };

  const handleDelete = async (cveId) => {
    try {
      await api.delete(`/api/cves/${encodeURIComponent(cveId)}`);
      addToast("CVE deleted.", "success");
      setSelected(null);
      fetchCves();
    } catch (e) {
      addToast(errorMessage(e, "Failed to delete."), "error");
    }
    setDeleteConfirm(null);
  };

const fetchCves = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, per_page: perPage };
      if (search) params.search = search;
      if (cveSource) params.source = cveSource;
      if (severity) params.severity = severity;
      if (exploit) params.exploit_available = exploit;
      if (reviewStatus) params.review_status = reviewStatus;
      if (sentFilter) params.sent = sentFilter === "true";
      if (minCvss) params.min_cvss = parseFloat(minCvss);
      if (sortBy && sortBy !== "newest") params.sort_by = sortBy;
      const res = await api.get("/api/cves/", { params });
      const data = res.data || {};
      setCves(data.items || []);
      setPages(data.pages || 0);
    } catch {
      setCves([]);
      setPages(0);
    } finally {
      setLoading(false);
    }
  }, [page, search, cveSource, severity, exploit, reviewStatus, sentFilter, minCvss, sortBy]);

  useEffect(() => { fetchCves(); }, [fetchCves]);

  useEffect(() => {
    const sev = (searchParams.get("severity") || "").toUpperCase();
    setSeverity((prev) => (prev !== sev ? sev : prev));
    if (sev) setPage(1);
  }, [searchParams]);

  useEffect(() => {
    const cveId = searchParams.get("cve_id");
    if (!cveId) return;
    let ignore = false;
    (async () => {
      try {
        const res = await api.get(`/api/cves/${encodeURIComponent(cveId)}`);
        if (!ignore && res.data) setSelected(res.data);
      } catch { /* ignore */ }
    })();
    return () => { ignore = true; };
  }, [searchParams]);

  const handleSearch = (val) => { setSearch(val); setPage(1); };
  const clearSelected = () => {
    setSelected(null);
    if (searchParams.get("cve_id")) {
      searchParams.delete("cve_id");
      setSearchParams(searchParams, { replace: true });
    }
  };

  if (selected) {
    return (
      <div className="space-y-4">
        {flagModal && (
          <ConfirmModal
            message="Flag this CVE for review?"
            confirmLabel="Flag"
            withInput
            inputLabel="Note for analyst (optional)"
            inputPlaceholder="Add context about why you're flagging this..."
            onConfirm={(note) => handleFlag(flagModal, note)}
            onCancel={() => setFlagModal(null)}
          />
        )}
        <button onClick={clearSelected} className="text-sm text-gray-400 hover:text-white">&larr; Back to list</button>
        <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-6 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[#00d4ff] font-mono text-sm">{selected.cve_id}</span>
                <ReviewBadge status={selected.review_status} />
                <EditedBadge editedBy={selected.edited_by} />
                <SentBadge sentAt={selected.advisory_sent_at} sentBy={selected.advisory_sent_by} />
              </div>
              <h1 className="text-lg font-bold text-white mt-1">{selected.title || selected.cve_id}</h1>
              {selected.edited_by && (
                <p className="text-xs text-gray-600 mt-0.5">Last edited by {selected.edited_by}</p>
              )}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge value={selected.cvss_severity} />
              {canEdit && (
                <>
                  <button
                    onClick={() => setFlagModal(selected.cve_id)}
                    disabled={flagging}
                    className="px-3 py-1 text-xs rounded bg-[#38BDF8]/10 border border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20 disabled:opacity-50"
                  >
                    Flag for review
                  </button>
                  <button
                    onClick={() => setOpenAdvisory(cveToAdvisory(selected))}
                    className="px-3 py-1 text-xs rounded bg-[#38BDF8] text-[#2E2E38] font-semibold hover:bg-[#FFD700]"
                  >
                    Open in Advisory Editor
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div><span className="text-gray-500">CVSS Score</span><CvssBar score={selected.cvss_base_score} /></div>
            <div><span className="text-gray-500">Vendor</span><p className="text-white">{selected.vendor || "—"}</p></div>
            <div>
              <span className="text-gray-500">Exploit</span>
              <span className={`text-sm font-semibold block ${selected.exploit_available === "yes" ? "text-red-400" : selected.exploit_available === "no" ? "text-green-400" : "text-gray-400"}`}>
                {selected.exploit_available}
              </span>
            </div>
            <div>
              <span className="text-gray-500">Patch</span>
              <span className={`text-sm font-semibold block ${selected.patch_available === "yes" ? "text-green-400" : selected.patch_available === "no" ? "text-red-400" : "text-gray-400"}`}>
                {selected.patch_available}
              </span>
            </div>
          </div>

          {/* Enriched Products */}
          {(() => {
            const products = selected.enrichment_data?.affected_products || [];
            return products.length > 0 ? (
              <div>
                <span className="text-gray-500 text-sm">Affected Products (Enriched)</span>
                <div className="mt-1 border border-[#2a2a4a] rounded overflow-hidden">
                  <table className="w-full text-xs">
                    <thead><tr className="bg-[#0f0f23] text-gray-500 uppercase">
                      <th className="text-left px-3 py-1.5">Product</th>
                      <th className="text-left px-3 py-1.5">Versions</th>
                      <th className="text-left px-3 py-1.5">Notes</th>
                    </tr></thead>
                    <tbody>{products.map((p, i) => (
                      <tr key={i} className="border-t border-[#1e1e3a]">
                        <td className="px-3 py-1.5 text-white font-medium">{p.name || "—"}</td>
                        <td className="px-3 py-1.5 text-gray-400 font-mono">{p.versions || "—"}</td>
                        <td className="px-3 py-1.5 text-gray-500">{p.notes || "—"}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              </div>
            ) : selected.affected_products ? (
              <div><span className="text-gray-500 text-sm">Affected Products</span><p className="text-gray-300 text-sm mt-1">{selected.affected_products}</p></div>
            ) : null;
          })()}

          {/* Client Matches */}
          {(() => {
            const matches = selected.enrichment_data?.client_matches || [];
            return matches.length > 0 && (
              <div>
                <span className="text-gray-500 text-sm">Matched Clients</span>
                <div className="flex flex-wrap gap-2 mt-1">
                  {matches.map((m, i) => (
                    <span key={i} className="px-2 py-1 text-xs rounded border bg-yellow-900/20 border-yellow-800 text-[#38BDF8]">
                      {m.client_name || m.email || `Client #${m.client_id}`}
                      {m.confidence && <span className="text-yellow-600 ml-1">({m.confidence})</span>}
                    </span>
                  ))}
                </div>
              </div>
            );
          })()}

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

          {selected.description && (
            <div><span className="text-gray-500 text-sm">Description</span><p className="text-gray-300 text-sm mt-1 leading-relaxed whitespace-pre-wrap">{selected.description}</p></div>
          )}

          {selected.cvss_vector && (
            <div><span className="text-gray-500 text-sm">CVSS Vector</span><p className="text-gray-400 text-xs font-mono mt-1">{selected.cvss_vector}</p></div>
          )}

          {/* Source / Scraper info */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm border-t border-[#2a2a4a] pt-4">
            <div><span className="text-gray-500">Source</span><p className="text-gray-300 font-mono text-xs">{selected.source || "—"}</p></div>
            <div><span className="text-gray-500">Published</span><p className="text-gray-300 text-xs">{selected.published_at ? new Date(selected.published_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : "—"}</p></div>
            <div><span className="text-gray-500">Created</span><p className="text-gray-300 text-xs">{selected.created_at ? new Date(selected.created_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : "—"}</p></div>
            <div>
              <span className="text-gray-500">Links</span>
              <div className="flex gap-2 mt-0.5">
                {selected.source_url && <a href={selected.source_url} target="_blank" rel="noopener noreferrer" className="text-[#00d4ff] text-xs hover:underline">Source</a>}
                {selected.patch_url && <a href={selected.patch_url} target="_blank" rel="noopener noreferrer" className="text-green-400 text-xs hover:underline">Patch</a>}
                {!selected.source_url && !selected.patch_url && <span className="text-gray-600 text-xs">—</span>}
              </div>
            </div>
          </div>

          {user?.role === "admin" && (
            <div className="flex gap-2 pt-2 border-t border-[#2a2a4a]">
              <button onClick={() => setDeleteConfirm(selected.cve_id)} className="px-3 py-1.5 text-xs rounded border border-red-800 text-red-400 hover:bg-red-900/30">Delete</button>
            </div>
          )}

        </div>
        {deleteConfirm && (
          <ConfirmModal
            message={`Delete CVE ${deleteConfirm}?`}
            confirmLabel="Delete"
            danger
            onConfirm={() => handleDelete(deleteConfirm)}
            onCancel={() => setDeleteConfirm(null)}
          />
        )}
        {openAdvisory && (
          <AdvisoryEditor
            advisory={openAdvisory}
            onSave={handleAdvisorySave}
            onApprove={() => {}}
            onClose={() => setOpenAdvisory(null)}
            onSend={handleAdvisorySend}
            onDone={() => { setOpenAdvisory(null); fetchCves(); }}
          />
        )}
      </div>
    );
  }

  // CLIENT ticket view — simplified card layout with search only
  if (isClient) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-bold text-white">Vulnerabilities</h1>
        <SearchBar onSearch={handleSearch} placeholder="Search CVEs..." initialValue={search} />
        {loading ? (
          <p className="text-gray-600 text-sm py-8 text-center">Loading...</p>
        ) : cves.length === 0 ? (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-8 text-center text-gray-600 text-sm">
            No vulnerabilities matching your profile.
          </div>
        ) : (
          <div className="space-y-3">
            {cves.map((c) => (
              <TicketCard key={c.id} item={c} type="cve" onClick={() => setSelected(c)} />
            ))}
          </div>
        )}
        <Pagination page={page} pages={pages} onPageChange={setPage} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-white">CVEs</h1>

      <div className="flex flex-wrap items-end gap-4">
        <div className="flex-1 min-w-[200px]">
          <SearchBar onSearch={handleSearch} placeholder="Search by CVE ID, title, vendor, product..." initialValue={search} />
        </div>
        <FilterSelect label="Source" value={cveSource} onChange={(v) => { setCveSource(v); setPage(1); }} options={cveSourceOptions} />
        <FilterSelect label="Severity" value={severity} onChange={(v) => { setSeverity(v); setPage(1); }} options={
          cascadingOptions.severities?.length > 0
            ? cascadingOptions.severities.map((s) => ({ value: s.value, label: `${s.value} (${s.count})` }))
            : severityOptions
        } />
        <FilterSelect label="Exploit" value={exploit} onChange={(v) => { setExploit(v); setPage(1); }} options={
          cascadingOptions.exploit_values?.length > 0
            ? cascadingOptions.exploit_values.map((s) => ({ value: s.value, label: `${s.value} (${s.count})` }))
            : exploitOptions
        } />
        <FilterSelect label="Sent" value={sentFilter} onChange={(v) => { setSentFilter(v); setPage(1); }} options={[
          { value: "true", label: "Sent" },
          { value: "false", label: "Not Sent" },
        ]} />
        <FilterSelect label="Reviewed" value={reviewStatus} onChange={(v) => { setReviewStatus(v); setPage(1); }} options={reviewStatusOptions} />
        <FilterSelect label="Sort" value={sortBy} onChange={(v) => { setSortBy(v); setPage(1); }} options={[
          { value: "newest", label: "Newest" },
          { value: "oldest", label: "Oldest" },
          { value: "cvss_desc", label: "Highest CVSS" },
        ]} />
      </div>

      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2a4a] text-gray-500 text-xs uppercase">
              <th className="text-left px-4 py-3 font-medium w-40">CVE ID</th>
              <th className="text-left px-4 py-3 font-medium">Title</th>
              <th className="text-left px-4 py-3 font-medium w-20">Vendor</th>
              <th className="text-left px-4 py-3 font-medium w-24">CVSS</th>
              <th className="text-left px-4 py-3 font-medium w-20">Severity</th>
              <th className="text-left px-4 py-3 font-medium w-20">Source</th>
              <th className="text-left px-4 py-3 font-medium w-20">Clients</th>
              <th className="text-left px-4 py-3 font-medium w-24">Published</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-600">Loading...</td></tr>
            ) : cves.length === 0 ? (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-600">No CVEs found.</td></tr>
            ) : cves.map((c) => {
              const clientMatches = c.enrichment_data?.client_matches || [];
              return (
              <tr
                key={c.id}
                onClick={() => setSelected(c)}
                className="border-b border-[#1e1e3a] hover:bg-[#1a1a2e] cursor-pointer transition-colors"
              >
                <td className="px-4 py-3 text-[#00d4ff] font-mono text-xs">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {c.cve_id}
                    <ReviewBadge status={c.review_status} />
                    <EditedBadge editedBy={c.edited_by} />
                    <SentBadge sentAt={c.advisory_sent_at} sentBy={c.advisory_sent_by} />
                  </div>
                </td>
                <td className="px-4 py-3 text-gray-200 truncate max-w-[200px]">{c.title || "—"}</td>
                <td className="px-4 py-3 text-gray-400 text-xs truncate max-w-[100px]">{c.vendor || "—"}</td>
                <td className="px-4 py-3"><CvssBar score={c.cvss_base_score} /></td>
                <td className="px-4 py-3"><SeverityBadge value={c.cvss_severity} /></td>
                <td className="px-4 py-3 text-gray-500 text-xs font-mono">{c.source || "—"}</td>
                <td className="px-4 py-3">
                  {clientMatches.length > 0 ? (
                    <span
                      title={clientMatches.map(m => m.client_name || m.email || `#${m.client_id}`).join(", ")}
                      className="text-[10px] font-semibold px-1.5 py-0.5 rounded border bg-yellow-900/20 border-yellow-800 text-[#38BDF8]"
                    >
                      {clientMatches.length} matched
                    </span>
                  ) : (
                    <span className="text-gray-600 text-xs">—</span>
                  )}
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs">{c.published_at ? new Date(c.published_at).toLocaleDateString() : "—"}</td>
              </tr>
            );})}
          </tbody>
        </table>
      </div>

      <Pagination page={page} pages={pages} onPageChange={setPage} />
    </div>
  );
}
