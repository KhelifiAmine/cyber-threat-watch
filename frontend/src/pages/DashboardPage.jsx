import { useState, useEffect, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../api/axios";
import { errorMessage } from "../api/errors";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import ClientDashboard from "../components/dashboard/ClientDashboard";
import TrendChart from "../components/charts/TrendChart";
import ReportEditor from "../components/report/ReportEditor";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, CartesianGrid,
} from "recharts";

// ─── Helpers ──────────────────────────────────────────────

function relTime(isoStr) {
  if (!isoStr) return "never";
  const diff = Date.now() - new Date(isoStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const SEV_COLORS = {
  CRITICAL: "#ef4444", critical: "#ef4444",
  HIGH: "#f97316", high: "#f97316",
  MEDIUM: "#eab308", medium: "#eab308",
  LOW: "#22c55e", low: "#22c55e",
  INFO: "#6b7280", info: "#6b7280",
};

const SECTOR_COLORS = [
  "#38BDF8", "#00d4ff", "#ff6b6b", "#51cf66", "#cc5de8",
  "#ff922b", "#339af0", "#20c997", "#f06595", "#868e96",
];

const STATUS_LABEL = { overdue: "Overdue", needs_attention: "Needs attention", current: "Current" };
const STATUS_DOT = { overdue: "bg-red-500", needs_attention: "bg-yellow-500", current: "bg-green-500" };
const STATUS_TEXT = { overdue: "text-red-400", needs_attention: "text-yellow-400", current: "text-green-400" };

// ─── Report Builder Modal ───────────────────────────────

const REPORT_MODULES = [
  { id: "overview", label: "Executive Summary" },
  { id: "severity", label: "Severity Breakdown" },
  { id: "products", label: "Top Affected Products" },
  { id: "sectors", label: "Sector Exposure" },
  { id: "regions", label: "Regional Threat Landscape" },
  { id: "exposure", label: "Client Exposure Analysis" },
  { id: "advisories", label: "Advisory History" },
  { id: "cves", label: "Critical CVEs" },
];

function ReportBuilderModal({ onClose, onGenerate }) {
  const [selected, setSelected] = useState(new Set(REPORT_MODULES.map((m) => m.id)));
  const [days, setDays] = useState("30");
  const [reportType, setReportType] = useState("general");
  const [clients, setClients] = useState([]);
  const [selectedClientId, setSelectedClientId] = useState("");
  const [generating, setGenerating] = useState(false);
  const { addToast } = useToast();

  useEffect(() => {
    api.get("/api/notifications/clients")
      .then((res) => setClients(res.data || []))
      .catch(() => {});
  }, []);

  const toggle = (id) =>
    setSelected((prev) => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });

  const generate = async () => {
    setGenerating(true);
    try {
      const res = await api.post("/api/reports/generate-data", {
        report_type: reportType,
        days: parseInt(days),
        modules: [...selected],
        client_id: reportType === "client" && selectedClientId ? selectedClientId : undefined,
      });
      onGenerate(reportType, res.data);
    } catch (err) {
      addToast(errorMessage(err, "Failed to generate report data."), "error");
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-6 w-[420px] shadow-2xl max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold text-sm">Build Report</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-lg leading-none">&times;</button>
        </div>

        {/* Report Type Toggle */}
        <div className="mb-4">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Report Type</p>
          <div className="flex gap-2">
            {[["general", "General"], ["client", "Client"]].map(([v, l]) => (
              <button key={v} onClick={() => setReportType(v)}
                className={`flex-1 px-3 py-1.5 text-xs rounded border transition-colors ${reportType === v ? "bg-[#38BDF8] text-black border-[#38BDF8] font-semibold" : "border-[#2a2a4a] text-gray-400 hover:border-[#38BDF8]/40 hover:text-white"}`}
              >{l}</button>
            ))}
          </div>
        </div>

        <div className="mb-4">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Time Period</p>
          <div className="flex gap-2">
            {[["7", "7 days"], ["30", "30 days"], ["90", "90 days"]].map(([v, l]) => (
              <button key={v} onClick={() => setDays(v)}
                className={`px-3 py-1.5 text-xs rounded border transition-colors ${days === v ? "bg-[#38BDF8] text-black border-[#38BDF8] font-semibold" : "border-[#2a2a4a] text-gray-400 hover:border-[#38BDF8]/40 hover:text-white"}`}
              >{l}</button>
            ))}
          </div>
        </div>

        {/* Client selector (only for client reports) */}
        {reportType === "client" && clients.length > 0 && (
          <div className="mb-4">
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Select Client</p>
            <select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)}
              className="w-full px-3 py-1.5 bg-[#0f0f23] border border-[#2a2a4a] rounded text-xs text-gray-300 focus:outline-none focus:border-[#38BDF8]/50">
              <option value="">Select a client...</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.full_name} — {c.company || c.email}</option>)}
            </select>
          </div>
        )}

        <div className="mb-5">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Modules</p>
          <div className="space-y-2">
            {REPORT_MODULES.map(({ id, label }) => (
              <label key={id} className="flex items-center gap-2.5 cursor-pointer group">
                <input type="checkbox" checked={selected.has(id)} onChange={() => toggle(id)} className="accent-[#38BDF8] w-3.5 h-3.5" />
                <span className="text-sm text-gray-300 group-hover:text-white transition-colors">{label}</span>
              </label>
            ))}
          </div>
        </div>
        <div className="flex gap-3">
          <button onClick={generate} disabled={selected.size === 0 || generating || (reportType === "client" && !selectedClientId)}
            className="flex-1 py-2 text-sm rounded bg-[#38BDF8] text-black font-semibold hover:bg-yellow-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
            {generating ? "Generating..." : "Generate Report"}
          </button>
          <button onClick={onClose} className="px-4 py-2 text-sm rounded border border-[#2a2a4a] text-gray-400 hover:text-white hover:border-[#3a3a5a] transition-colors">
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Severity Bar (replaces pie chart) ───────────────────

function SeverityBars({ data }) {
  const entries = Object.entries(data || {}).filter(([, v]) => v > 0);
  const total = entries.reduce((s, [, v]) => s + v, 0) || 1;
  const navigate = useNavigate();

  if (entries.length === 0) return <p className="text-gray-600 text-sm">No severity data</p>;

  return (
    <div className="space-y-2">
      {entries.map(([sev, count]) => (
        <button key={sev} onClick={() => navigate(`/cves?severity=${sev.toUpperCase()}`)}
          className="w-full flex items-center gap-3 group hover:bg-[#161628] rounded px-1 py-0.5 transition-colors">
          <span className="text-xs text-gray-400 capitalize w-16 text-left">{sev}</span>
          <div className="flex-1 h-4 bg-[#1a1a2e] rounded overflow-hidden">
            <div className="h-full rounded transition-all" style={{ width: `${(count / total) * 100}%`, backgroundColor: SEV_COLORS[sev] || "#6b7280" }} />
          </div>
          <span className="text-xs font-mono text-gray-300 w-8 text-right">{count}</span>
        </button>
      ))}
    </div>
  );
}

// ─── Client Detail Expansion ─────────────────────────────

function ClientDetail({ recipientId, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    if (!recipientId) return;
    setLoading(true);
    api.get(`/api/dashboard/client-detail/${recipientId}`)
      .then((res) => setData(res.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [recipientId]);

  if (loading) return <div className="py-6 text-center text-gray-500 text-sm">Loading client data...</div>;
  if (!data) return <div className="py-6 text-center text-gray-500 text-sm">Failed to load client data</div>;

  const { client, product_inventory, cve_exposure, threat_exposure, advisory_history, stats } = data;

  return (
    <div className="bg-[#0d0d1a] border border-[#2a2a4a] rounded-lg p-5 mt-2 mb-4 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-white font-semibold text-sm">{client.name}</h3>
          <p className="text-gray-500 text-xs">{client.company}{client.sector ? ` · ${client.sector}` : ""} · {client.email}</p>
          <p className="text-gray-600 text-[10px] mt-1">
            {stats.total_products} products monitored · {stats.total_cves} matching CVEs · {stats.unsent_cves} unsent
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={onClose} className="text-gray-500 hover:text-white text-lg leading-none px-1">&times;</button>
        </div>
      </div>

      {/* Product Inventory */}
      <div>
        <h4 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Product Inventory</h4>
        {product_inventory.length === 0 ? (
          <p className="text-gray-600 text-xs">No products in inventory</p>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {product_inventory.map((p, i) => (
              <div key={i} className="bg-[#12121e] border border-[#1e1e36] rounded px-3 py-2 text-xs">
                <p className="text-gray-300 font-medium truncate">{p.product}</p>
                <p className="text-gray-600 text-[10px]">{p.vendor}{p.version ? ` v${p.version}` : ""}</p>
                <p className={`font-mono mt-0.5 ${p.cve_count > 0 ? "text-red-400" : "text-green-400"}`}>
                  {p.cve_count > 0 ? `${p.cve_count} CVEs` : "No known CVEs"}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* CVE Exposure Table */}
      <div>
        <h4 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">CVE Exposure ({cve_exposure.length})</h4>
        {cve_exposure.length === 0 ? (
          <p className="text-gray-600 text-xs">No matching CVEs</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-500 uppercase tracking-wider border-b border-[#2a2a4a]">
                  <th className="text-left py-1.5 pr-2">CVE ID</th>
                  <th className="text-left py-1.5 pr-2">Product</th>
                  <th className="text-center py-1.5 pr-2">CVSS</th>
                  <th className="text-center py-1.5 pr-2">Severity</th>
                  <th className="text-center py-1.5 pr-2">Status</th>
                  <th className="text-right py-1.5">Age</th>
                </tr>
              </thead>
              <tbody>
                {cve_exposure.slice(0, 20).map((cve) => (
                  <tr key={cve.cve_id} className="border-b border-[#1e1e36]/50 hover:bg-[#161628] transition-colors">
                    <td className="py-1.5 pr-2">
                      <Link to={`/cves?cve_id=${cve.cve_id}`} className="text-[#00d4ff] hover:text-[#38BDF8] font-mono">
                        {cve.cve_id}
                      </Link>
                    </td>
                    <td className="py-1.5 pr-2 text-gray-400 truncate max-w-[120px]">{cve.product}</td>
                    <td className="py-1.5 pr-2 text-center">
                      <span className={`font-mono font-bold ${(cve.cvss || 0) >= 9 ? "text-red-400" : (cve.cvss || 0) >= 7 ? "text-orange-400" : "text-yellow-400"}`}>
                        {cve.cvss?.toFixed(1) || "—"}
                      </span>
                    </td>
                    <td className="py-1.5 pr-2 text-center">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium"
                        style={{ color: SEV_COLORS[cve.severity?.toLowerCase()] || "#6b7280" }}>
                        {cve.severity || "—"}
                      </span>
                    </td>
                    <td className="py-1.5 pr-2 text-center">
                      {cve.sent_at ? (
                        <span className="text-green-400 text-[10px]">Sent {new Date(cve.sent_at).toLocaleDateString("en-GB", { day: "numeric", month: "short" })}</span>
                      ) : (
                        <span className="text-red-400 text-[10px] font-medium">Unsent</span>
                      )}
                    </td>
                    <td className="py-1.5 text-right text-gray-600">{cve.age_hours < 24 ? `${cve.age_hours}h` : `${Math.floor(cve.age_hours / 24)}d`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {cve_exposure.length > 20 && (
              <p className="text-gray-600 text-[10px] mt-1">+ {cve_exposure.length - 20} more CVEs</p>
            )}
          </div>
        )}
      </div>

      {/* Threat Exposure */}
      {threat_exposure.length > 0 && (
        <div>
          <h4 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Threat Exposure</h4>
          <div className="space-y-1.5">
            {threat_exposure.slice(0, 5).map((t) => (
              <div key={t.id} className="flex items-center justify-between text-xs bg-[#12121e] rounded px-3 py-2">
                <span className="text-gray-300 truncate mr-3">{t.title}</span>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="font-mono text-orange-400">{t.risk_score}</span>
                  {t.sent_at ? (
                    <span className="text-green-400 text-[10px]">Sent</span>
                  ) : (
                    <span className="text-red-400 text-[10px]">Unsent</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Advisory History */}
      {advisory_history.length > 0 && (
        <div>
          <h4 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Advisory History</h4>
          <div className="space-y-1">
            {advisory_history.slice(0, 8).map((a, i) => (
              <div key={i} className="flex items-center gap-3 text-xs text-gray-400">
                <span className="text-gray-600 w-16 shrink-0">
                  {new Date(a.sent_at).toLocaleDateString("en-GB", { day: "numeric", month: "short" })}
                </span>
                <span className="text-[#00d4ff] font-mono">{a.identifier}</span>
                <span className="truncate">{a.title}</span>
                <span className="text-green-500 text-[10px] shrink-0">Sent</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────

export default function DashboardPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const isClient = user?.role === "client";
  const isAnalyst = user?.role === "admin" || user?.role === "analyst";

  // Data state (hooks must run unconditionally)
  const [summary, setSummary] = useState(null);
  const [trends, setTrends] = useState([]);
  const [trendDays, setTrendDays] = useState(7);
  const [topProducts, setTopProducts] = useState([]);
  const [sectors, setSectors] = useState([]);
  const [attentionItems, setAttentionItems] = useState(null);
  const [clientBoard, setClientBoard] = useState([]);
  const [spiderSchedule, setSpiderSchedule] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showReportBuilder, setShowReportBuilder] = useState(false);
  const [reportEditor, setReportEditor] = useState(null); // { reportType, data }
  const [regionalData, setRegionalData] = useState([]);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  // Client expansion state
  const [expandedClientId, setExpandedClientId] = useState(null);

  const fetchData = useCallback(async () => {
    if (isClient) return; // ClientDashboard handles its own data
    try {
      const [summaryRes, trendsRes, productsRes, sectorsRes, attentionRes, clientBoardRes, regionalRes] =
        await Promise.all([
          api.get("/api/dashboard/summary"),
          api.get(`/api/dashboard/trends?days=${trendDays}`),
          api.get("/api/dashboard/top-products?days=30&limit=10"),
          api.get("/api/dashboard/sectors?days=30"),
          api.get("/api/dashboard/attention-items"),
          api.get("/api/dashboard/client-status-board"),
          api.get("/api/dashboard/regional-landscape?days=30"),
        ]);
      setSummary(summaryRes.data);
      setTrends(trendsRes.data.trends || []);
      setTopProducts(productsRes.data || []);
      setSectors(sectorsRes.data || []);
      setAttentionItems(attentionRes.data);
      setClientBoard(clientBoardRes.data || []);
      setRegionalData(regionalRes.data || []);
      setLastRefresh(new Date());
    } catch {
      setError("Failed to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }, [trendDays, isClient]);

  useEffect(() => {
    if (isClient) return; // ClientDashboard handles its own lifecycle
    fetchData();
    let spiderFetch;
    if (isAnalyst) {
      spiderFetch = () => api.get("/api/scraper/schedule").then((r) => setSpiderSchedule(r.data)).catch(() => {});
      spiderFetch();
    }
    const interval = setInterval(() => { fetchData(); spiderFetch?.(); }, 30000);
    return () => clearInterval(interval);
  }, [isClient, isAnalyst, fetchData]);

  // CLIENT users get their own dashboard component
  if (isClient) return <ClientDashboard />;

  if (loading) return <div className="text-gray-400 p-8">Loading dashboard...</div>;
  if (error) return <div className="text-red-400 p-8">{error}</div>;

  const severity = summary?.severity_breakdown || {};
  const attention = attentionItems || {};
  const totalAttention = attention.pending_review_count || 0;

  const allSpiders = [
    ...(spiderSchedule?.vendor_spiders || []),
    ...(spiderSchedule?.news_spiders || []),
  ];
  const healthySpiders = allSpiders.filter((s) => s.enabled !== false && s.last_status === "SUCCESS").length;
  const totalSpiders = allSpiders.filter((s) => s.enabled !== false).length;

  return (
    <div className="space-y-6">

      {/* ══════════════════════════════════════════════════════
          SECTION A: ACTION REQUIRED
          ══════════════════════════════════════════════════════ */}
      <div>
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-xl font-bold text-white">
              {user?.full_name ? `${user.full_name.split(" ")[0]}, ` : ""}
              {totalAttention > 0 ? (
                <span className="text-[#38BDF8]">{totalAttention} item{totalAttention !== 1 ? "s" : ""} need{totalAttention === 1 ? "s" : ""} your attention.</span>
              ) : (
                <span className="text-green-400">all clear.</span>
              )}
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] text-gray-600">
              {lastRefresh.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}
            </span>
            <button onClick={() => setShowReportBuilder(true)}
              className="px-4 py-1.5 text-xs rounded bg-[#38BDF8] text-black font-semibold hover:bg-yellow-300 transition-colors">
              Build Report
            </button>
          </div>
        </div>

        {/* Action Required: 3-column layout */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* Unsent Advisories — work queue */}
          <div className="lg:col-span-2 bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4">
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">Unsent Advisories</h3>
            {(attention.unsent_cves?.length > 0 || attention.unsent_threats?.length > 0) ? (
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-600 uppercase tracking-wider border-b border-[#2a2a4a]">
                    <th className="text-left py-1 pr-2">ID</th>
                    <th className="text-left py-1 pr-2">Title</th>
                    <th className="text-left py-1 pr-2">Affected Clients</th>
                    <th className="text-center py-1 pr-2">Score</th>
                    <th className="text-right py-1">Age</th>
                  </tr>
                </thead>
                <tbody>
                  {attention.unsent_cves?.map((c) => (
                    <tr key={c.cve_id} className="border-b border-[#1e1e36]/50 hover:bg-[#161628] transition-colors">
                      <td className="py-1.5 pr-2">
                        <Link to={`/cves?cve_id=${c.cve_id}`} className="text-[#00d4ff] hover:text-[#38BDF8] font-mono text-xs">
                          {c.cve_id}
                        </Link>
                      </td>
                      <td className="py-1.5 pr-2 text-gray-300 truncate max-w-[200px]">{c.title}</td>
                      <td className="py-1.5 pr-2">
                        {c.affected_clients?.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {c.affected_clients.map((name) => (
                              <span key={name} className="px-1.5 py-0.5 rounded bg-[#38BDF8]/10 text-[#38BDF8] text-[10px] font-medium">{name}</span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-gray-600 text-[10px]">No client match</span>
                        )}
                      </td>
                      <td className="py-1.5 pr-2 text-center">
                        <span className={`font-mono font-bold ${(c.cvss || 0) >= 9 ? "text-red-400" : (c.cvss || 0) >= 7 ? "text-orange-400" : "text-yellow-400"}`}>
                          {c.cvss?.toFixed(1)}
                        </span>
                      </td>
                      <td className="py-1.5 text-right text-gray-600">{relTime(c.created_at)}</td>
                    </tr>
                  ))}
                  {attention.unsent_threats?.map((t) => (
                    <tr key={t.id} className="border-b border-[#1e1e36]/50 hover:bg-[#161628] transition-colors">
                      <td className="py-1.5 pr-2">
                        <Link to="/threats" className="text-orange-400 hover:text-[#38BDF8] text-xs font-medium">THREAT</Link>
                      </td>
                      <td className="py-1.5 pr-2 text-gray-300 truncate max-w-[200px]">{t.title}</td>
                      <td className="py-1.5 pr-2"><span className="text-gray-600 text-[10px]">—</span></td>
                      <td className="py-1.5 pr-2 text-center">
                        <span className="font-mono font-bold text-orange-400">{t.risk_score}</span>
                      </td>
                      <td className="py-1.5 text-right text-gray-600">{relTime(t.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-gray-600 text-xs py-4 text-center">No unsent high-risk items</p>
            )}
          </div>

          {/* Right column: Review Queue + Spider Alerts */}
          <div className="space-y-4">
            {/* Pending Review */}
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4 text-center">
              <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-2">Pending Review</h3>
              <p className="text-2xl font-bold text-[#38BDF8] mb-2">{attention.pending_review_count || 0}</p>
              <Link to="/review" className="text-xs text-gray-400 hover:text-[#38BDF8] transition-colors">
                Go to Queue &rarr;
              </Link>
            </div>

            {/* Spider Alerts */}
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4">
              <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-2">Spider Alerts</h3>
              {attention.failed_spiders?.length > 0 ? (
                <ul className="space-y-1.5">
                  {attention.failed_spiders.map((f, i) => (
                    <li key={i} className="text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-red-400 font-medium">{f.name}</span>
                        <span className="text-[10px] text-gray-600">{relTime(f.failed_at)}</span>
                      </div>
                      {f.last_error && <p className="text-[10px] text-gray-600 truncate mt-0.5">{f.last_error}</p>}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-gray-600">No failures in last 24h</p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════
          SECTION B: CLIENT STATUS BOARD
          ══════════════════════════════════════════════════════ */}
      <div>
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Client Status Board</h2>
        {clientBoard.length === 0 ? (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-6 text-center text-gray-600 text-sm">
            No active clients. Add clients in <Link to="/clients" className="text-[#38BDF8] hover:underline">Client Management</Link>.
          </div>
        ) : (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-xs uppercase tracking-wider border-b border-[#2a2a4a] bg-[#0d0d1a]">
                  <th className="text-left py-2.5 pl-4 pr-2">Client</th>
                  <th className="text-left py-2.5 pr-2">Sector</th>
                  <th className="text-center py-2.5 pr-2">Products</th>
                  <th className="text-center py-2.5 pr-2">Open CVEs</th>
                  <th className="text-center py-2.5 pr-2">Unsent</th>
                  <th className="text-left py-2.5 pr-2">Last Advisory</th>
                  <th className="text-center py-2.5 pr-4">Status</th>
                </tr>
              </thead>
              <tbody>
                {clientBoard.map((client) => (
                  <ClientRow
                    key={client.user_id}
                    client={client}
                    isExpanded={expandedClientId === client.id}
                    onToggle={() => setExpandedClientId(expandedClientId === client.id ? null : client.id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════
          SECTION C: INTELLIGENCE OVERVIEW
          ══════════════════════════════════════════════════════ */}
      <div>
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Intelligence Overview</h2>

        {/* Row 1: Trend + Severity */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
          {/* Threat Trends (wider) */}
          <div className="lg:col-span-2 bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs uppercase tracking-wider text-gray-500">Threat Intake</h3>
              <div className="flex gap-1">
                {[7, 14, 30].map((d) => (
                  <button key={d} onClick={() => setTrendDays(d)}
                    className={`px-2 py-0.5 text-[10px] rounded transition-colors ${trendDays === d ? "bg-[#38BDF8] text-black font-semibold" : "text-gray-500 hover:text-white"}`}>
                    {d}d
                  </button>
                ))}
              </div>
            </div>
            <TrendChart data={trends} />
          </div>

          {/* Severity Breakdown (narrower) */}
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-4">Severity Distribution</h3>
            <SeverityBars data={severity} />
          </div>
        </div>

        {/* Row 2: Products + Sectors */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Top Products */}
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs uppercase tracking-wider text-gray-500">Top Affected Products</h3>
            </div>
            {topProducts.length === 0 ? (
              <p className="text-gray-600 text-sm">No product data yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height={topProducts.length * 32 + 20}>
                <BarChart data={topProducts} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" width={180}
                    tick={({ x, y, payload }) => (
                      <text x={x} y={y} dy={4} textAnchor="end" fill="#d1d5db" fontSize={11}>
                        {payload.value?.length > 24 ? payload.value.slice(0, 22) + "\u2026" : payload.value}
                      </text>
                    )}
                    axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "#1a1a2e", border: "1px solid #2a2a4a", borderRadius: 6, fontSize: 12 }} labelStyle={{ color: "#38BDF8" }} />
                  <Bar dataKey="count" fill="#38BDF8" radius={[0, 4, 4, 0]} cursor="pointer"
                    onClick={(data) => data?.name && navigate(`/cves?search=${encodeURIComponent(data.name)}`)} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Sector Exposure */}
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs uppercase tracking-wider text-gray-500">Sector Exposure</h3>
            </div>
            {sectors.length === 0 ? (
              <p className="text-gray-600 text-sm">No sector data yet.</p>
            ) : (
              <div className="flex items-center gap-4">
                <ResponsiveContainer width="55%" height={220}>
                  <PieChart>
                    <Pie data={sectors} dataKey="count" nameKey="sector" cx="50%" cy="50%"
                      outerRadius={80} innerRadius={40} stroke="#0a0a15" strokeWidth={2}
                      cursor="pointer" onClick={(data) => data?.sector && navigate(`/news?sector=${encodeURIComponent(data.sector)}`)}>
                      {sectors.map((_, i) => <Cell key={i} fill={SECTOR_COLORS[i % SECTOR_COLORS.length]} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#1a1a2e", border: "1px solid #2a2a4a", borderRadius: 6, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex-1 space-y-1.5">
                  {sectors.slice(0, 8).map((s, i) => (
                    <button key={s.sector} onClick={() => navigate(`/news?sector=${encodeURIComponent(s.sector)}`)}
                      className="flex items-center gap-2 text-xs w-full hover:bg-[#161628] -mx-1 px-1 rounded transition-colors">
                      <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: SECTOR_COLORS[i % SECTOR_COLORS.length] }} />
                      <span className="text-gray-300 truncate flex-1 text-left">{s.sector}</span>
                      <span className="text-gray-500 font-mono">{s.count}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Row 3: Regional Landscape */}
        {regionalData.length > 0 && (
          <div className="mt-4 bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs uppercase tracking-wider text-gray-500">Regional Threat Landscape</h3>
              <div className="flex items-center gap-3 text-[9px] text-gray-500">
                <span className="flex items-center gap-1"><span className="w-2 h-2 bg-[#f97316] rounded-sm" /> Threats</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 bg-[#0ea5e9] rounded-sm" /> News</span>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={regionalData.length * 32 + 20}>
              <BarChart data={regionalData} layout="vertical" margin={{ left: 10, right: 20 }}>
                <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="region" width={120}
                  tick={{ fill: "#d1d5db", fontSize: 11 }}
                  axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#1a1a2e", border: "1px solid #2a2a4a", borderRadius: 6, fontSize: 12 }} />
                <CartesianGrid strokeDasharray="3 3" stroke="#1e1e3a" horizontal={false} />
                <Bar dataKey="threat_count" stackId="a" fill="#f97316" name="Threats" barSize={16} />
                <Bar dataKey="news_count" stackId="a" fill="#0ea5e9" name="News" radius={[0, 4, 4, 0]} barSize={16} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════
          SECTION D: QUICK ACCESS FOOTER
          ══════════════════════════════════════════════════════ */}
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg px-5 py-3">
        <div className="flex items-center justify-between flex-wrap gap-3 text-xs">
          {/* Operational health indicators */}
          <div className="flex items-center gap-6 text-gray-400">
            <span>
              Collection: <span className={totalSpiders > 0 && healthySpiders === totalSpiders ? "text-green-400" : "text-orange-400"}>
                {healthySpiders}/{totalSpiders} spiders healthy
              </span>
            </span>
            <span>
              Throughput: <span className="text-gray-300">{summary?.overview?.threats_last_24h || 0} threats + {summary?.overview?.new_cves_24h || 0} CVEs (24h)</span>
            </span>
            <span>
              Review: <span className={attention.pending_review_count > 0 ? "text-[#38BDF8]" : "text-gray-500"}>
                {attention.pending_review_count || 0} pending
              </span>
            </span>
            <span>
              Clients: <span className="text-gray-300">{clientBoard.length} active</span>
              {clientBoard.filter((c) => c.status === "overdue").length > 0 && (
                <span className="text-red-400 ml-1">· {clientBoard.filter((c) => c.status === "overdue").length} overdue</span>
              )}
            </span>
          </div>

          {/* Spider mini-status (analyst only) */}
          {isAnalyst && allSpiders.length > 0 && (
            <div className="flex items-center gap-1">
              {allSpiders.filter((s) => s.enabled !== false).map((s) => (
                <span key={s.spider} title={`${s.spider}: ${s.last_status || "unknown"} ${relTime(s.last_run_at)}`}
                  className={`w-2 h-2 rounded-full ${s.last_status === "SUCCESS" ? "bg-green-400" : s.last_status === "FAILURE" ? "bg-red-400" : s.last_status === "RUNNING" ? "bg-yellow-400" : "bg-gray-600"}`} />
              ))}
              <Link to="/scraper" className="text-[10px] text-gray-600 hover:text-[#38BDF8] ml-2 transition-colors">
                Manage &rarr;
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Report Builder Modal */}
      {showReportBuilder && (
        <ReportBuilderModal
          onClose={() => setShowReportBuilder(false)}
          onGenerate={(type, data) => {
            setShowReportBuilder(false);
            setReportEditor({ reportType: type, data });
          }}
        />
      )}

      {/* Report Editor Overlay */}
      {reportEditor && (
        <ReportEditor
          reportType={reportEditor.reportType}
          data={reportEditor.data}
          onClose={() => setReportEditor(null)}
        />
      )}
    </div>
  );
}

// ─── Client Row (with inline expansion) ──────────────────

function ClientRow({ client, isExpanded, onToggle }) {
  return (
    <>
      <tr onClick={onToggle}
        className={`border-b border-[#1e1e36] cursor-pointer transition-colors ${isExpanded ? "bg-[#161628]" : "hover:bg-[#161628]"}`}>
        <td className="py-2.5 pl-4 pr-2">
          <div className="flex items-center gap-2">
            <span className={`text-[10px] transition-transform ${isExpanded ? "rotate-90" : ""}`}>{"\u25B6"}</span>
            <span className="text-gray-200 font-medium">{client.name}</span>
          </div>
        </td>
        <td className="py-2.5 pr-2 text-gray-500">{client.sector || "—"}</td>
        <td className="py-2.5 pr-2 text-center text-gray-400">{client.products_count}</td>
        <td className="py-2.5 pr-2 text-center">
          <span className={client.open_cves > 0 ? "text-orange-400 font-medium" : "text-gray-500"}>{client.open_cves}</span>
        </td>
        <td className="py-2.5 pr-2 text-center">
          {client.unsent_cves > 0 ? (
            <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 font-bold text-xs">{client.unsent_cves}</span>
          ) : (
            <span className="text-gray-500">0</span>
          )}
        </td>
        <td className="py-2.5 pr-2 text-gray-400 text-xs">
          {client.last_advisory_at ? relTime(client.last_advisory_at) : <span className="text-gray-600">never</span>}
        </td>
        <td className="py-2.5 pr-4 text-center">
          <span className="inline-flex items-center gap-1.5 text-xs" title={STATUS_LABEL[client.status]}>
            <span className={`w-2 h-2 rounded-full ${STATUS_DOT[client.status] || "bg-gray-500"}`} />
            <span className={`text-[10px] ${STATUS_TEXT[client.status] || "text-gray-500"}`}>{STATUS_LABEL[client.status]}</span>
          </span>
        </td>
      </tr>
      {isExpanded && client.id && (
        <tr>
          <td colSpan={7} className="p-0">
            <ClientDetail recipientId={client.id} onClose={onToggle} />
          </td>
        </tr>
      )}
      {isExpanded && !client.id && (
        <tr>
          <td colSpan={7} className="px-4 py-3">
            <p className="text-gray-500 text-xs">No notification recipient record linked. Add products in <Link to="/clients" className="text-[#38BDF8] hover:underline">Client Management</Link>.</p>
          </td>
        </tr>
      )}
    </>
  );
}
