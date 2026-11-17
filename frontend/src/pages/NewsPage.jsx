import { useState, useEffect, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import api from "../api/axios";
import { useAuth } from "../context/AuthContext";
import Pagination from "../components/ui/Pagination";
import SearchBar from "../components/ui/SearchBar";
import FilterSelect from "../components/ui/FilterSelect";
import TicketCard from "../components/ui/TicketCard";
import { errorMessage } from "../api/errors";
import { useToast } from "../context/ToastContext";
import AdvisoryEditor from "../components/review/AdvisoryEditor";
import ConfirmModal from "../components/ui/ConfirmModal";

// ─── Helpers ─────────────────────────────────────────────

function newsToAdvisory(article) {
  const d = article.published_at ? new Date(article.published_at) : (article.created_at ? new Date(article.created_at) : new Date());
  const advisoryId = `${String(d.getFullYear()).slice(2)}${String(d.getMonth()+1).padStart(2,"0")}${String(d.getDate()).padStart(2,"0")}-${String(article.id).padStart(4,"0")}`;
  return {
    kind: "news",
    newsId: article.id,
    cveId: null,
    threatId: null,
    proposalId: null,
    proposalKind: null,
    origin: null,
    flagNote: null,
    advisoryId,
    title: article.title || "",
    summary: article.summary || "",
    description: article.description || "",
    publishedAt: article.published_at
      ? new Date(article.published_at).toLocaleDateString("en-GB", { day: "2-digit", month: "long", year: "numeric" })
      : "",
    sectors: article.sectors || [],
    source: article.source || "",
    sourceUrl: article.url || "",
    language: article.language || "en",
    advisory_sent_at: article.advisory_sent_at,
    advisory_sent_by: article.advisory_sent_by,
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
    enrichedProducts: [],
    impactPoints: [],
    remediationSteps: [],
    tempMitigation: [],
    additionalResources: [],
    clientMatches: [],
  };
}

const STATUS_COLORS = {
  NEW: "text-blue-400 bg-blue-900/20 border-blue-800",
  FLAGGED: "text-yellow-400 bg-yellow-900/20 border-yellow-800",
  REVIEWED: "text-green-400 bg-green-900/20 border-green-800",
  DISMISSED: "text-gray-400 bg-gray-800/20 border-gray-700",
};

const SOURCE_OPTIONS = [
  { value: "BleepingComputer", label: "BleepingComputer" },
  { value: "TheHackerNews", label: "TheHackerNews" },
  { value: "DarkReading", label: "DarkReading" },
  { value: "SecurityWeek", label: "SecurityWeek" },
];

const SECTOR_OPTIONS = [
  { value: "Banking & Finance", label: "Banking & Finance" },
  { value: "Energy & Utilities", label: "Energy & Utilities" },
  { value: "Healthcare", label: "Healthcare" },
  { value: "Telecom", label: "Telecom" },
  { value: "Government", label: "Government" },
  { value: "Manufacturing", label: "Manufacturing" },
  { value: "Retail", label: "Retail" },
  { value: "Education", label: "Education" },
  { value: "Transportation", label: "Transportation" },
  { value: "Technology", label: "Technology" },
];

const SENT_OPTIONS = [
  { value: "true", label: "Sent" },
  { value: "false", label: "Not Sent" },
];

const STATUS_OPTIONS = [
  { value: "NEW", label: "New" },
  { value: "FLAGGED", label: "Flagged" },
  { value: "REVIEWED", label: "Reviewed" },
  { value: "DISMISSED", label: "Dismissed" },
];

const SORT_OPTIONS = [
  { value: "newest", label: "Newest" },
  { value: "oldest", label: "Oldest" },
];

// ─── Badges ──────────────────────────────────────────────

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


export default function NewsPage() {
  const { addToast } = useToast();
  const { user } = useAuth();
  const isClient = user?.role === "client";
  const canEdit = user?.role === "admin" || user?.role === "analyst";
  const [searchParams] = useSearchParams();
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("");
  const [sector, setSector] = useState(() => searchParams.get("sector") || "");
  const [sent, setSent] = useState("");
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState("newest");
  // Detail view
  const [selected, setSelected] = useState(null);
  // Advisory editor (only when explicitly opened)
  const [openAdvisory, setOpenAdvisory] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const limit = 20;

  const fetchArticles = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, limit, sort };
      if (search) params.search = search;
      if (source) params.source = source;
      if (sector) params.sector = sector;
      if (sent) params.sent = sent;
      if (status) params.status = status;
      const res = await api.get("/api/news", { params });
      setArticles(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch {
      addToast("Failed to load news articles.", "error");
    } finally {
      setLoading(false);
    }
  }, [page, limit, search, source, sector, sent, status, sort, addToast]);

  useEffect(() => { fetchArticles(); }, [fetchArticles]);
  useEffect(() => { setPage(1); }, [search, source, sector, sent, status, sort]);

  const handleFlag = async (articleId) => {
    try {
      await api.post(`/api/news/${articleId}/flag`, {});
      addToast("Article flagged for review.", "success");
      fetchArticles();
      if (selected?.id === articleId) setSelected((s) => ({ ...s, status: "FLAGGED" }));
    } catch (e) {
      addToast(errorMessage(e, "Failed to flag article."), "error");
    }
  };

  const handleDelete = async (articleId) => {
    try {
      await api.delete(`/api/news/${articleId}`);
      addToast("Article deleted.", "success");
      setSelected(null);
      fetchArticles();
    } catch (e) {
      addToast(errorMessage(e, "Failed to delete."), "error");
    }
    setDeleteConfirm(null);
  };

  const handleSave = async (form) => {
    await api.patch(`/api/news/${form.newsId}`, {
      title: form.title,
      summary: form.summary,
      description: form.description,
      sectors: form.sectors,
    });
  };

  const handleSend = async (form, recipientIds) => {
    const res = await api.post(`/api/news/${form.newsId}/send`, {
      recipient_ids: recipientIds.length ? recipientIds : null,
    });
    return res.data;
  };

  // ── Detail view ──────────────────────────────────────────
  if (selected) {
    return (
      <div className="space-y-4">
        <button onClick={() => setSelected(null)} className="text-sm text-gray-400 hover:text-white">
          &larr; Back to list
        </button>

        <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-6 space-y-4">
          {/* Header */}
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${STATUS_COLORS[selected.status] || STATUS_COLORS.NEW}`}>
                  {selected.status}
                </span>
                <EditedBadge editedBy={selected.edited_by} />
                <SentBadge sentAt={selected.advisory_sent_at} sentBy={selected.advisory_sent_by} />
              </div>
              <h1 className="text-lg font-bold text-white mt-1">{selected.title}</h1>
              {selected.edited_by && (
                <p className="text-xs text-gray-600 mt-0.5">Last edited by {selected.edited_by}</p>
              )}
            </div>
            <div className="flex items-center gap-2 flex-wrap shrink-0">
              <span className="text-[10px] px-2 py-0.5 rounded border border-cyan-800 text-cyan-400 bg-cyan-900/20 font-semibold">
                {selected.source}
              </span>
              {canEdit && (
                <>
                  <button
                    onClick={() => handleFlag(selected.id)}
                    className="px-3 py-1 text-xs rounded bg-[#38BDF8]/10 border border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20"
                  >
                    Flag for review
                  </button>
                  <button
                    onClick={() => setOpenAdvisory(newsToAdvisory(selected))}
                    className="px-3 py-1 text-xs rounded bg-[#38BDF8] text-[#2E2E38] font-semibold hover:bg-[#FFD700]"
                  >
                    Open in Advisory Editor
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
            <div>
              <span className="text-gray-500 text-xs block">Published</span>
              <span className="text-gray-300">{selected.published_at ? new Date(selected.published_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : "—"}</span>
            </div>
            <div>
              <span className="text-gray-500 text-xs block">Language</span>
              <span className="text-gray-300 uppercase">{selected.language || "en"}</span>
            </div>
            <div>
              <span className="text-gray-500 text-xs block">Original</span>
              {selected.url ? (
                <a href={selected.url} target="_blank" rel="noopener noreferrer" className="text-[#00d4ff] text-xs hover:underline truncate block max-w-[220px]">
                  {selected.url}
                </a>
              ) : <span className="text-gray-600">—</span>}
            </div>
          </div>

          {/* Sectors */}
          {(selected.sectors || []).length > 0 && (
            <div>
              <span className="text-gray-500 text-xs block mb-1">Sectors</span>
              <div className="flex flex-wrap gap-1">
                {selected.sectors.map((s, i) => (
                  <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-[#2E2E38] text-[#38BDF8] border border-[#38BDF8]/20">
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Regions */}
          {(selected.affected_regions || []).length > 0 && (
            <div>
              <span className="text-gray-500 text-xs block mb-1">Affected Regions</span>
              <div className="flex flex-wrap gap-1">
                {selected.affected_regions.map((r, i) => (
                  <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-[#0f0f23] border border-[#2a2a4a] text-blue-400">
                    {r}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Summary */}
          {selected.summary && (
            <div>
              <span className="text-gray-500 text-xs block mb-1">Summary</span>
              <p className="text-gray-300 text-sm leading-relaxed">{selected.summary}</p>
            </div>
          )}

          {/* Description */}
          {selected.description && (
            <div>
              <span className="text-gray-500 text-xs block mb-1">Full Article</span>
              <p className="text-gray-300 text-sm leading-relaxed whitespace-pre-wrap">{selected.description}</p>
            </div>
          )}

          {user?.role === "admin" && (
            <div className="flex gap-2 pt-2 border-t border-[#2a2a4a]">
              <button onClick={() => setDeleteConfirm(selected.id)} className="px-3 py-1.5 text-xs rounded border border-red-800 text-red-400 hover:bg-red-900/30">Delete</button>
            </div>
          )}
        </div>

        {deleteConfirm && (
          <ConfirmModal
            message="Delete this news article?"
            confirmLabel="Delete"
            danger
            onConfirm={() => handleDelete(deleteConfirm)}
            onCancel={() => setDeleteConfirm(null)}
          />
        )}
        {openAdvisory && (
          <AdvisoryEditor
            advisory={openAdvisory}
            onSave={handleSave}
            onApprove={async () => {}}
            onClose={async () => {}}
            onSend={handleSend}
            onDone={() => {
              setOpenAdvisory(null);
              fetchArticles();
            }}
          />
        )}
      </div>
    );
  }

  // CLIENT ticket view
  if (isClient) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-bold text-white">Security News</h1>
        <SearchBar onSearch={setSearch} placeholder="Search news..." initialValue={search} />
        {loading ? (
          <p className="text-gray-600 text-sm py-8 text-center">Loading...</p>
        ) : articles.length === 0 ? (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-8 text-center text-gray-600 text-sm">
            No news matching your profile.
          </div>
        ) : (
          <div className="space-y-3">
            {articles.map((a) => (
              <TicketCard key={a.id} item={a} type="news" onClick={() => setSelected(a)} />
            ))}
          </div>
        )}
        <Pagination page={page} total={Math.ceil(total / limit)} onPageChange={setPage} />
      </div>
    );
  }

  // ── List view ─────────────────────────────────────────────
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-white">News</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <SearchBar
          onSearch={setSearch}
          placeholder="Search news articles..."
          initialValue={search}
        />
        <FilterSelect value={source} onChange={setSource} options={SOURCE_OPTIONS} label="Source" />
        <FilterSelect value={sector} onChange={setSector} options={SECTOR_OPTIONS} label="Sector" />
        <FilterSelect value={status} onChange={setStatus} options={STATUS_OPTIONS} label="Status" />
        <FilterSelect value={sent} onChange={setSent} options={SENT_OPTIONS} label="Sent" />
        <FilterSelect value={sort} onChange={setSort} options={SORT_OPTIONS} label="Sort" />
      </div>

      {/* Table */}
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#2a2a4a] text-gray-500 uppercase">
              <th className="text-left px-4 py-2.5 font-medium">Title</th>
              <th className="text-left px-4 py-2.5 font-medium w-28">Source</th>
              <th className="text-left px-4 py-2.5 font-medium w-44">Sectors</th>
              <th className="text-left px-4 py-2.5 font-medium w-24">Published</th>
              <th className="text-left px-4 py-2.5 font-medium w-20">Status</th>
              <th className="text-left px-4 py-2.5 font-medium w-20">Tags</th>
              <th className="text-left px-4 py-2.5 font-medium w-24">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-600">Loading...</td>
              </tr>
            ) : articles.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-600">No news articles found.</td>
              </tr>
            ) : (
              articles.map((a) => (
                <tr
                  key={a.id}
                  className="border-b border-[#1e1e3a] hover:bg-[#161628] cursor-pointer transition-colors"
                  onClick={() => setSelected(a)}
                >
                  <td className="px-4 py-2.5 text-gray-200 max-w-[300px] truncate">
                    {(a.title || "").slice(0, 80)}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-[10px] px-2 py-0.5 rounded border border-cyan-800 text-cyan-400 bg-cyan-900/20 font-semibold">
                      {a.source}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {(a.sectors || []).slice(0, 2).map((s, i) => (
                        <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-[#2E2E38] text-[#38BDF8] border border-[#38BDF8]/20">
                          {s}
                        </span>
                      ))}
                      {(a.sectors || []).length > 2 && (
                        <span className="text-[10px] text-gray-500">+{a.sectors.length - 2}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-gray-400">
                    {a.published_at ? new Date(a.published_at).toLocaleDateString() : "—"}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${STATUS_COLORS[a.status] || STATUS_COLORS.NEW}`}>
                      {a.status}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1 flex-wrap">
                      <EditedBadge editedBy={a.edited_by} />
                      <SentBadge sentAt={a.advisory_sent_at} sentBy={a.advisory_sent_by} />
                    </div>
                  </td>
                  <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
                    <div className="flex gap-1">
                      <button
                        onClick={() => setOpenAdvisory(newsToAdvisory(a))}
                        className="text-[10px] px-2 py-0.5 rounded bg-[#38BDF8] text-[#2E2E38] font-semibold hover:bg-[#FFD700]"
                      >
                        Send
                      </button>
                      <button
                        onClick={() => handleFlag(a.id)}
                        title="Flag for review"
                        className="text-[10px] px-1.5 py-0.5 rounded border border-[#2a2a4a] text-gray-500 hover:text-yellow-400 hover:border-yellow-800"
                      >
                        &#x22EE;
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <Pagination
        page={page}
        total={Math.ceil(total / limit)}
        onPageChange={setPage}
      />

      {openAdvisory && (
        <AdvisoryEditor
          advisory={openAdvisory}
          onSave={handleSave}
          onApprove={async () => {}}
          onClose={async () => {}}
          onSend={handleSend}
          onDone={() => {
            setOpenAdvisory(null);
            fetchArticles();
          }}
        />
      )}
    </div>
  );
}
