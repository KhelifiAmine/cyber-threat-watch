import { useState, useEffect, useCallback } from "react";
import api from "../api/axios";
import Pagination from "../components/ui/Pagination";
import FilterSelect from "../components/ui/FilterSelect";
import AdvisoryEditor from "../components/review/AdvisoryEditor";
import { useToast } from "../context/ToastContext";
import { errorMessage } from "../api/errors";

// ─── Filter options ────────────────────────────────────────────────────────────

const kindOptions = [
  { value: "", label: "All" },
  { value: "cve", label: "CVEs" },
  { value: "threat", label: "Threats" },
  { value: "news", label: "News" },
];

const severityOptions = [
  { value: "", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ageText(isoDate) {
  if (!isoDate) return "—";
  const diffMs = Date.now() - new Date(isoDate).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

function flaggedBy(proposal) {
  if (proposal.origin === "MANUAL") {
    const src = proposal.source || "";
    return src.startsWith("manual:") ? src.slice(7) : src || "Analyst";
  }
  // SCRAPER: source is the spider name
  return proposal.source || "System";
}

// ─── Priority helpers ──────────────────────────────────────────────────────────

const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function getPriority(item) {
  const pf = item.proposed_fields || {};
  const isCve = item.kind === "cve";

  const rawProposed = isCve ? pf.cvss_base_score : pf.risk_score;
  const score =
    rawProposed != null && rawProposed !== ""
      ? parseFloat(rawProposed)
      : item.priority_score;

  if (score != null && !isNaN(score)) {
    if (isCve) {
      if (score >= 9.0) return 0;
      if (score >= 7.0) return 1;
      if (score >= 4.0) return 2;
      return 3;
    } else {
      if (score >= 90) return 0;
      if (score >= 70) return 1;
      if (score >= 40) return 2;
      return 3;
    }
  }

  const proposedSev = (
    (isCve ? pf.cvss_severity : pf.severity) || ""
  ).toLowerCase();
  const sev = proposedSev || (item.priority_severity || "").toLowerCase();
  return priorityOrder[sev] ?? 4;
}

function priorityLabel(p) {
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "—"][p] ?? "—";
}

function priorityColor(p) {
  return [
    "text-red-400 bg-red-900/20 border-red-800",
    "text-orange-400 bg-orange-900/20 border-orange-800",
    "text-yellow-400 bg-yellow-900/20 border-yellow-800",
    "text-green-400 bg-green-900/20 border-green-800",
    "text-gray-500 bg-gray-800/20 border-gray-700",
  ][p] ?? "text-gray-500 bg-gray-800/20 border-gray-700";
}

// ─── Convert a proposal to the normalized advisory shape ──────────────────────

function generateAdvisoryId(isoDate) {
  const d = isoDate ? new Date(isoDate) : new Date();
  const yy = String(d.getFullYear()).slice(2);
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yy}${mm}${dd}`;
}

function normalizeRemediationSteps(steps = []) {
  return steps.map((s, i) => {
    if (typeof s === "string") {
      return { label: String(i + 1), action: s, reference_label: "", reference_url: "" };
    }
    return {
      label: s.label ?? String(i + 1),
      action: s.action ?? "",
      reference_label: s.reference_label ?? "",
      reference_url: s.reference_url ?? "",
    };
  });
}

function proposalToAdvisory(proposal) {
  const proposed = proposal.proposed_fields || {};
  const current = proposal.current_fields || {};
  const enrichment =
    proposed.enrichment_data || current.enrichment_data || {};

  const advisoryId = generateAdvisoryId(proposal.created_at);

  if (proposal.kind === "news") {
    return {
      kind: "news",
      newsId: proposal.news_article_id,
      cveId: null,
      threatId: null,
      proposalId: proposal.id,
      proposalKind: "news",
      origin: proposal.origin,
      flagNote: proposal.flag_note || null,
      clientMatches: proposal.client_matches || [],
      advisoryId,
      title: proposed.title || current.title || "",
      summary: proposed.summary || current.summary || "",
      description: proposed.description || current.description || "",
      publishedAt: proposed.published_at || current.published_at || "",
      sectors: proposed.sectors || current.sectors || [],
      source: proposed.source || current.source || "",
      sourceUrl: proposed.url || current.url || "",
      language: proposed.language || current.language || "en",
      advisory_sent_at: proposal.client_email_sent_at || null,
      advisory_sent_by: null,
      // Enrichment data (LLM-extracted structured fields)
      enrichmentSummary: enrichment.summary || "",
      enrichmentConclusion: enrichment.conclusion || "",
      enrichmentRegions: enrichment.affected_regions || [],
      enrichedProducts: enrichment.affected_products || [],
      impactPoints: enrichment.impact_points || [],
      remediationSteps: enrichment.remediation_steps || [],
      tempMitigation: enrichment.temp_mitigation || [],
      // CVE/Threat fields (not used for news)
      cveIds: "",
      cvssScore: null,
      cvssSeverity: "",
      cvssVector: "",
      vendor: "",
      patchAvailable: "unknown",
      patchUrl: "",
      exploitAvailable: "unknown",
      riskScore: null,
      severity: "",
      threatType: "",
      ttpCodes: "",
      regions: "",
      additionalResources: [],
    };
  }

  const isCve = proposal.kind === "cve";

  if (isCve) {
    return {
      kind: "cve",
      cveId: proposal.cve_id,
      threatId: null,
      proposalId: proposal.id,
      proposalKind: "cve",
      origin: proposal.origin,
      flagNote: proposal.flag_note || null,
      clientMatches: proposal.client_matches || [],
      advisoryId,
      title: proposed.title || current.title || "",
      summary: proposed.description || current.description || "",
      description: proposed.description || current.description || "",
      publishedAt: "",
      cveIds: proposal.cve_id || "",
      cvssScore: proposed.cvss_base_score ?? current.cvss_base_score ?? null,
      cvssSeverity: (proposed.cvss_severity || current.cvss_severity || "").toUpperCase(),
      cvssVector: proposed.cvss_vector || current.cvss_vector || "",
      vendor: proposed.vendor || current.vendor || "",
      patchAvailable: proposed.patch_available || current.patch_available || "unknown",
      patchUrl: proposed.patch_url || current.patch_url || "",
      exploitAvailable: proposed.exploit_available || current.exploit_available || "unknown",
      sourceUrl: proposed.source_url || current.source_url || "",
      riskScore: null,
      severity: "",
      threatType: "",
      ttpCodes: "",
      regions: "",
      enrichedProducts: enrichment.affected_products || [],
      impactPoints: enrichment.impact_points || [],
      remediationSteps: normalizeRemediationSteps(enrichment.remediation_steps),
      tempMitigation: enrichment.temp_mitigation || [],
      enrichmentSummary: enrichment.summary || "",
      enrichmentConclusion: enrichment.conclusion || "",
      enrichmentRegions: enrichment.affected_regions || [],
      additionalResources:
        (proposed.source_url || current.source_url)
          ? [{ name: "Source", url: proposed.source_url || current.source_url }]
          : [],
      advisory_sent_at: proposal.client_email_sent_at || null,
      advisory_sent_by: null,
    };
  }

  // Threat proposal
  return {
    kind: "threat",
    cveId: null,
    threatId: proposal.threat_id,
    proposalId: proposal.id,
    proposalKind: "threat",
    origin: proposal.origin,
    flagNote: proposal.flag_note || null,
    clientMatches: proposal.client_matches || [],
    advisoryId,
    title: proposed.title || current.title || "",
    summary: proposed.description || current.description || "",
    description: proposed.description || current.description || "",
    publishedAt: "",
    cveIds: "",
    cvssScore: null,
    cvssSeverity: "",
    cvssVector: "",
    vendor: "",
    patchAvailable: "unknown",
    patchUrl: "",
    exploitAvailable: "unknown",
    riskScore: proposed.risk_score ?? current.risk_score ?? null,
    severity: (proposed.severity || current.severity || "").toLowerCase(),
    threatType: proposed.threat_type || current.threat_type || "",
    ttpCodes: proposed.ttp_codes || current.ttp_codes || "",
    regions: proposed.regions || current.regions || "",
    sourceUrl: proposed.source_url || current.source_url || "",
    enrichedProducts: enrichment.affected_products || [],
    impactPoints: enrichment.impact_points || [],
    remediationSteps: normalizeRemediationSteps(enrichment.remediation_steps),
    tempMitigation: enrichment.temp_mitigation || [],
    enrichmentSummary: enrichment.summary || "",
    enrichmentConclusion: enrichment.conclusion || "",
    enrichmentRegions: enrichment.affected_regions || [],
    additionalResources: [],
    advisory_sent_at: proposal.client_email_sent_at || null,
    advisory_sent_by: null,
  };
}

// ─── Queue row ────────────────────────────────────────────────────────────────

function QueueRow({ proposal, onOpen }) {
  const p = getPriority(proposal);
  const label = priorityLabel(p);
  const colorCls = priorityColor(p);
  const isCve = proposal.kind === "cve";
  const isNews = proposal.kind === "news";

  const title = isNews
    ? proposal.proposed_fields?.title || proposal.current_fields?.title || "Untitled News"
    : isCve
    ? proposal.proposed_fields?.title || proposal.current_fields?.title || proposal.cve_id || "Untitled CVE"
    : proposal.proposed_fields?.title || proposal.current_fields?.title || proposal.threat_title || "Untitled Threat";

  const age = ageText(proposal.created_at);
  const by = flaggedBy(proposal);
  const matchCount = proposal.client_matches?.length || 0;
  const matchTip = matchCount > 0
    ? proposal.client_matches.map(m => `${m.client_name} (${m.confidence})`).join(", ")
    : null;

  // Detect which fields differ between proposed and current for SCRAPER tickets
  const changedFields = (() => {
    if (proposal.origin !== "SCRAPER") return null;
    const pf = proposal.proposed_fields || {};
    const cf = proposal.current_fields || {};
    const keys = Object.keys(pf).filter(k => pf[k] != null && pf[k] !== "" && pf[k] !== cf[k]);
    return keys.length ? keys.slice(0, 3).join(", ") : null;
  })();

  return (
    <button
      onClick={() => onOpen(proposal)}
      className="w-full text-left bg-[#12121e] hover:bg-[#1a1a2e] border border-[#2a2a4a] hover:border-[#3a3a5a] rounded-lg px-4 py-3 transition-colors group"
    >
      {/* ── Row 1: Kind / Title / Badges ── */}
      <div className="flex items-center gap-3">
        {/* Kind */}
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border shrink-0 ${
          isCve
            ? "text-blue-300 bg-blue-900/20 border-blue-800"
            : isNews
            ? "text-cyan-300 bg-cyan-900/20 border-cyan-800"
            : "text-purple-300 bg-purple-900/20 border-purple-800"
        }`}>
          {isCve ? "CVE" : isNews ? "NEWS" : "THREAT"}
        </span>

        {/* Title */}
        <span className="flex-1 text-sm text-gray-200 truncate group-hover:text-white transition-colors">
          {title}
        </span>

        {/* Priority */}
        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border shrink-0 ${colorCls}`}>
          {label}
        </span>

        {/* Client matches */}
        {matchCount > 0 && (
          <span
            title={matchTip}
            className="text-[10px] font-semibold px-2 py-0.5 rounded border shrink-0 text-[#38BDF8] bg-yellow-900/20 border-yellow-800"
          >
            {matchCount} client{matchCount !== 1 ? "s" : ""} matched
          </span>
        )}

        {/* Sent */}
        {proposal.client_email_sent_at && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border bg-green-900/30 text-green-400 border-green-700/50 shrink-0">
            SENT
          </span>
        )}

        {/* Arrow */}
        <svg className="w-4 h-4 text-gray-700 group-hover:text-gray-400 shrink-0 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 5l7 7-7 7" />
        </svg>
      </div>

      {/* ── Row 2: Context — who / why / age ── */}
      <div className="flex items-center gap-4 mt-1.5 pl-[52px]">
        {/* Who flagged */}
        <span className="text-[10px] text-gray-500">
          {proposal.origin === "SCRAPER" ? "System" : "Flagged by"}{" "}
          <span className="text-gray-400">{by}</span>
        </span>

        {/* Why / what changed */}
        {proposal.flag_note ? (
          <span className="text-[10px] text-gray-500 truncate max-w-[260px]" title={proposal.flag_note}>
            "{proposal.flag_note.slice(0, 80)}{proposal.flag_note.length > 80 ? "…" : ""}"
          </span>
        ) : changedFields ? (
          <span className="text-[10px] text-gray-500 truncate max-w-[260px]">
            New data: <span className="text-gray-400">{changedFields}</span>
          </span>
        ) : null}

        {/* Age */}
        <span className="text-[10px] text-gray-600 ml-auto shrink-0">
          Waiting <span className="text-gray-400">{age}</span>
        </span>
      </div>
    </button>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ReviewPage() {
  const { addToast } = useToast();

  const [proposals, setProposals] = useState([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(0);
  const [kind, setKind] = useState("");
  const [severity, setSeverity] = useState("");
  const [queueSort, setQueueSort] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // The proposal currently open in the editor (null = none)
  const [activeProposal, setActiveProposal] = useState(null);
  // Create-from-scratch: a blank advisory (no proposal backing it)
  const [newAdvisory, setNewAdvisory] = useState(null);
  const [showKindPicker, setShowKindPicker] = useState(false);

  // ── Fetch queue ──
  const fetchProposals = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = { status: "PENDING", page, per_page: 50 };
      if (kind) params.kind = kind;
      if (queueSort) params.sort_by = queueSort;
      const res = await api.get("/api/proposals/", { params });
      let items = res.data?.items || [];

      if (severity !== "") {
        const targetPriority = { critical: 0, high: 1, medium: 2, low: 3 }[severity];
        if (targetPriority !== undefined) {
          items = items.filter((p) => getPriority(p) === targetPriority);
        }
      }

      // Search filter — matches title, CVE ID, vendor, source
      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        items = items.filter((p) => {
          const pf = p.proposed_fields || {};
          const cf = p.current_fields || {};
          const title = (pf.title || cf.title || "").toLowerCase();
          const cveId = (p.cve_id || "").toLowerCase();
          const vendor = (pf.vendor || cf.vendor || "").toLowerCase();
          const source = (pf.source || cf.source || p.source || "").toLowerCase();
          const desc = (pf.description || cf.description || "").toLowerCase();
          return title.includes(q) || cveId.includes(q) || vendor.includes(q) || source.includes(q) || desc.includes(q);
        });
      }

      items.sort((a, b) => {
        const pa = getPriority(a);
        const pb = getPriority(b);
        if (pa !== pb) return pa - pb;
        return (a.created_at || "") < (b.created_at || "") ? -1 : 1;
      });

      setProposals(items);
      setPages(res.data?.pages || 0);
    } catch {
      setError("Failed to load queue.");
      setProposals([]);
    } finally {
      setLoading(false);
    }
  }, [kind, severity, queueSort, searchQuery, page]);

  useEffect(() => {
    fetchProposals();
  }, [fetchProposals]);

  // ── Editor callbacks ──

  const handleSave = async (form) => {
    if (form.kind === "news" && form.newsId) {
      await api.patch(`/api/news/${form.newsId}`, {
        title: form.title,
        summary: form.summary,
        description: form.description,
        sectors: form.sectors,
      });
      return;
    }

    const enrichment_data = {
      summary: form.summary || "",
      affected_products: form.enrichedProducts || [],
      impact_points: form.impactPoints || [],
      remediation_steps: form.remediationSteps || [],
      temp_mitigation: form.tempMitigation || [],
    };

    if (form.kind === "cve" && form.cveId) {
      await api.patch(`/api/cves/${form.cveId}`, {
        title: form.title || null,
        description: form.description || null,
        cvss_base_score: form.cvssScore ?? null,
        cvss_severity: form.cvssSeverity || null,
        cvss_vector: form.cvssVector || null,
        vendor: form.vendor || null,
        patch_available: form.patchAvailable || "unknown",
        exploit_available: form.exploitAvailable || "unknown",
        patch_url: form.patchUrl || null,
        source_url: form.sourceUrl || null,
        enrichment_data,
      });
    } else if (form.kind === "threat" && form.threatId) {
      await api.patch(`/api/threats/${form.threatId}`, {
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
    }
  };

  const handleApprove = async (form) => {
    if (!form.proposalId || !form.proposalKind) return;
    await api.post(
      `/api/proposals/${form.proposalKind}/${form.proposalId}/apply`,
      { fields: [], overrides: {} }
    );
  };

  const handleClose = async (form) => {
    if (!form.proposalId || !form.proposalKind) return;
    try {
      await api.post(
        `/api/proposals/${form.proposalKind}/${form.proposalId}/reject`,
        {}
      );
      addToast("Ticket closed.", "info");
    } catch (e) {
      addToast(errorMessage(e, "Failed to close ticket."), "error");
      throw e;
    }
  };

  const handleSend = async (form, recipientIds) => {
    if (!form.proposalId || !form.proposalKind) {
      throw new Error("No proposal associated with this advisory.");
    }
    const res = await api.post(
      `/api/proposals/${form.proposalKind}/${form.proposalId}/send`,
      { recipient_ids: recipientIds?.length ? recipientIds : null }
    );
    return res.data;
  };

  const handleDone = () => {
    setActiveProposal(null);
    fetchProposals();
  };

  // ── Create from scratch ──

  function blankAdvisory(kind) {
    const now = new Date();
    const advisoryId = `${String(now.getFullYear()).slice(2)}${String(now.getMonth()+1).padStart(2,"0")}${String(now.getDate()).padStart(2,"0")}`;
    return {
      kind,
      cveId: null,
      threatId: null,
      proposalId: null,
      proposalKind: null,
      origin: null,
      flagNote: null,
      advisoryId,
      title: "",
      summary: "",
      description: "",
      publishedAt: now.toLocaleDateString("en-GB", { day: "2-digit", month: "long", year: "numeric" }),
      cveIds: "",
      cvssScore: null,
      cvssSeverity: "",
      cvssVector: "",
      vendor: "",
      patchAvailable: "unknown",
      patchUrl: "",
      exploitAvailable: "unknown",
      riskScore: null,
      severity: "medium",
      threatType: "",
      ttpCodes: "",
      regions: "",
      sourceUrl: "",
      enrichedProducts: [],
      impactPoints: [],
      remediationSteps: [],
      tempMitigation: [],
      additionalResources: [],
    };
  }

  const handleSaveNew = async (form) => {
    const enrichment_data = {
      summary: form.summary || "",
      affected_products: form.enrichedProducts || [],
      impact_points: form.impactPoints || [],
      remediation_steps: form.remediationSteps || [],
      temp_mitigation: form.tempMitigation || [],
    };

    if (form.kind === "threat") {
      if (!form.threatId) {
        const res = await api.post("/api/threats/", {
          title: form.title || "Untitled Threat",
          description: form.description || "",
          source: "Manual",
          severity: form.severity || "medium",
          risk_score: form.riskScore ?? 0,
          threat_type: form.threatType || null,
          ttp_codes: form.ttpCodes || null,
          regions: form.regions || null,
          source_url: form.sourceUrl || null,
          enrichment_data,
        });
        addToast("Threat created.", "success");
        return { threatId: res.data.id };
      }
      await api.patch(`/api/threats/${form.threatId}`, {
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
    } else if (form.kind === "cve") {
      if (!form.cveId) {
        const cve_id = form.cveIds?.split(",")[0]?.trim() || `CTW-${Date.now()}`;
        const res = await api.post("/api/cves/", {
          cve_id,
          title: form.title || null,
          description: form.description || null,
          cvss_base_score: form.cvssScore ?? null,
          cvss_severity: form.cvssSeverity || null,
          cvss_vector: form.cvssVector || null,
          vendor: form.vendor || null,
          source: "Manual",
          enrichment_data,
        });
        addToast("CVE record created.", "success");
        return { cveId: res.data.cve_id };
      }
      await api.patch(`/api/cves/${encodeURIComponent(form.cveId)}`, {
        title: form.title || null,
        description: form.description || null,
        cvss_base_score: form.cvssScore ?? null,
        cvss_severity: form.cvssSeverity || null,
        cvss_vector: form.cvssVector || null,
        vendor: form.vendor || null,
        source_url: form.sourceUrl || null,
        enrichment_data,
      });
    }
  };

  const handleSendNew = async (form, recipientIds) => {
    const record_id = form.kind === "cve" ? form.cveId : String(form.threatId);
    if (!record_id) throw new Error("Save the advisory first before sending.");
    const res = await api.post("/api/advisory/send", {
      kind: form.kind,
      record_id,
      recipient_ids: recipientIds?.length ? recipientIds : null,
    });
    return res.data;
  };

  // ── Open editor ──
  const openEditor = (proposal) => {
    setActiveProposal(proposal);
  };

  return (
    <>
      {/* ── Queue list ── */}
      <div className="space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white">Review Queue</h1>
            <p className="text-gray-500 text-xs mt-1">
              Click any ticket to open the advisory editor. Save edits, send to clients, or mark as done.
            </p>
          </div>
          <div className="relative shrink-0">
            <button
              onClick={() => setShowKindPicker((v) => !v)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-[#38BDF8] text-[#2E2E38] hover:bg-[#FFD700] transition-colors"
            >
              + New Advisory
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {showKindPicker && (
              <div className="absolute right-0 mt-1 w-40 bg-[#12121e] border border-[#2a2a4a] rounded shadow-xl z-10">
                {["cve", "threat"].map((k) => (
                  <button
                    key={k}
                    onClick={() => { setNewAdvisory(blankAdvisory(k)); setShowKindPicker(false); }}
                    className="w-full text-left px-4 py-2 text-xs text-gray-200 hover:bg-[#1a1a2e] hover:text-white transition-colors"
                  >
                    {k === "cve" ? "CVE Advisory" : "Threat Advisory"}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Search + Filters */}
        <div className="flex flex-wrap items-end gap-4">
          {/* Search bar */}
          <div className="flex-1 min-w-[200px] max-w-md">
            <label className="block text-[10px] text-gray-500 mb-1">Search</label>
            <input
              type="text"
              className="w-full px-3 py-1.5 bg-[#0f0f23] border border-[#2a2a4a] rounded text-xs text-gray-300 placeholder-gray-600 focus:outline-none focus:border-[#38BDF8]/50"
              placeholder="Search by title, CVE ID, vendor, source..."
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
            />
          </div>
          <FilterSelect
            label="Kind"
            value={kind}
            onChange={(v) => { setKind(v || ""); setPage(1); }}
            options={kindOptions}
          />
          <FilterSelect
            label="Severity"
            value={severity}
            onChange={(v) => { setSeverity(v || ""); setPage(1); }}
            options={severityOptions}
          />
          <FilterSelect
            label="Sort"
            value={queueSort}
            onChange={(v) => { setQueueSort(v || ""); setPage(1); }}
            options={[
              { value: "", label: "Newest" },
              { value: "oldest", label: "Waiting Longest" },
              { value: "most_matches", label: "Most Matches" },
            ]}
          />
        </div>

        {error && <div className="text-red-400 text-sm">{error}</div>}

        {loading ? (
          <div className="text-gray-600 py-8 text-center">Loading…</div>
        ) : proposals.length === 0 ? (
          <div className="text-gray-600 py-8 text-center">No tickets in the queue.</div>
        ) : (
          <div className="space-y-2">
            {proposals.map((p) => (
              <QueueRow
                key={`${p.kind}-${p.id}`}
                proposal={p}
                onOpen={openEditor}
              />
            ))}
          </div>
        )}

        <Pagination page={page} pages={pages} onPageChange={setPage} />
      </div>

      {/* ── Advisory editor overlay — queue proposal ── */}
      {activeProposal && (
        <AdvisoryEditor
          advisory={proposalToAdvisory(activeProposal)}
          onSave={handleSave}
          onApprove={handleApprove}
          onClose={handleClose}
          onSend={handleSend}
          onDone={handleDone}
        />
      )}

      {/* ── Advisory editor overlay — create from scratch ── */}
      {newAdvisory && (
        <AdvisoryEditor
          advisory={newAdvisory}
          onSave={handleSaveNew}
          onApprove={() => {}}
          onClose={() => {}}
          onSend={handleSendNew}
          onDone={() => { setNewAdvisory(null); fetchProposals(); }}
        />
      )}
    </>
  );
}
