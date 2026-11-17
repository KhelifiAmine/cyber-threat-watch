import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, LineChart, Line, CartesianGrid } from "recharts";
import api from "../../api/axios";
import { useAuth } from "../../context/AuthContext";
import TicketCard from "../ui/TicketCard";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_COLORS = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#22c55e" };

export default function ClientDashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [feedFilter, setFeedFilter] = useState("all");

  useEffect(() => {
    api.get("/api/dashboard/my-exposure")
      .then((res) => setData(res.data))
      .catch(() => setError("Failed to load your exposure data."))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-gray-400 p-8">Loading your dashboard...</div>;
  if (error) return <div className="text-red-400 p-8">{error}</div>;
  if (!data) return <div className="text-gray-500 p-8">No exposure data available.</div>;

  const { client, product_inventory, cve_exposure, threat_exposure, advisory_history, stats } = data;

  // ── Chart data ──

  // Severity breakdown pie
  const sevCounts = {};
  cve_exposure.forEach((c) => {
    const s = (c.severity || "UNKNOWN").toUpperCase();
    sevCounts[s] = (sevCounts[s] || 0) + 1;
  });
  const severityData = SEV_ORDER
    .filter((s) => sevCounts[s] > 0)
    .map((s) => ({ name: s, value: sevCounts[s], color: SEV_COLORS[s] }));

  // Top affected products bar (top 8)
  const productData = product_inventory
    .filter((p) => p.cve_count > 0)
    .slice(0, 8)
    .map((p) => ({ name: p.product, cves: p.cve_count }));

  // CVE trend — group by week
  const weekCounts = {};
  cve_exposure.forEach((c) => {
    if (!c.created_at) return;
    const d = new Date(c.created_at);
    const weekStart = new Date(d);
    weekStart.setDate(d.getDate() - d.getDay());
    const key = weekStart.toISOString().slice(0, 10);
    weekCounts[key] = (weekCounts[key] || 0) + 1;
  });
  const trendData = Object.entries(weekCounts)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-12)
    .map(([week, count]) => ({
      week: new Date(week).toLocaleDateString("en-GB", { day: "numeric", month: "short" }),
      count,
    }));

  // Advisory history timeline — group by month
  const monthCounts = {};
  advisory_history.forEach((a) => {
    if (!a.sent_at) return;
    const key = a.sent_at.slice(0, 7); // YYYY-MM
    monthCounts[key] = (monthCounts[key] || 0) + 1;
  });
  const advisoryTrend = Object.entries(monthCounts)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-6)
    .map(([month, count]) => ({
      month: new Date(month + "-01").toLocaleDateString("en-GB", { month: "short", year: "2-digit" }),
      count,
    }));

  // Build unified feed
  const feed = [
    ...cve_exposure.map((c) => ({
      ...c, _type: "cve", _date: c.created_at, title: c.title || c.cve_id,
      severity: c.severity, source: c.source, description: c.title,
      cvss_base_score: c.cvss, advisory_sent_at: c.sent_at,
    })),
    ...threat_exposure.map((t) => ({
      ...t, _type: "threat", _date: t.created_at, severity: t.severity,
      risk_score: t.risk_score, advisory_sent_at: t.sent_at,
    })),
  ].sort((a, b) => new Date(b._date || 0) - new Date(a._date || 0));

  const filteredFeed = feedFilter === "all" ? feed : feed.filter((f) => f._type === feedFilter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white">
          Welcome, <span className="text-[#38BDF8]">{user?.full_name?.split(" ")[0] || "Client"}</span>
        </h1>
        <p className="text-sm text-gray-500 mt-0.5">
          {client.company || "Your organization"} &middot; {stats.total_products} products monitored
        </p>
      </div>

      {/* Stat cards — client-relevant only */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Products Monitored" value={stats.total_products} color="#38BDF8" />
        <StatCard label="Matching CVEs" value={stats.total_cves} color={stats.total_cves > 0 ? "#f97316" : "#22c55e"} />
        <StatCard label="Advisories Received" value={stats.advisories_received || 0} color="#00d4ff" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Severity Breakdown */}
        {severityData.length > 0 && (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-4">CVE Severity Breakdown</h3>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  dataKey="value"
                  stroke="none"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "#1a1a2e", border: "1px solid #2a2a4a", borderRadius: "8px" }}
                  itemStyle={{ color: "#e5e5e5" }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Top Affected Products */}
        {productData.length > 0 && (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-4">Most Affected Products</h3>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={productData} layout="vertical" margin={{ left: 10, right: 20 }}>
                <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 11 }} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: "#d1d5db", fontSize: 11 }} width={120} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#1a1a2e", border: "1px solid #2a2a4a", borderRadius: "8px" }}
                  itemStyle={{ color: "#e5e5e5" }}
                />
                <Bar dataKey="cves" fill="#f97316" radius={[0, 4, 4, 0]} name="CVEs" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Trend charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* CVE Trend */}
        {trendData.length > 1 && (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-4">New Vulnerabilities Over Time</h3>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e1e3a" />
                <XAxis dataKey="week" tick={{ fill: "#6b7280", fontSize: 10 }} />
                <YAxis tick={{ fill: "#6b7280", fontSize: 11 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#1a1a2e", border: "1px solid #2a2a4a", borderRadius: "8px" }}
                  itemStyle={{ color: "#e5e5e5" }}
                />
                <Line type="monotone" dataKey="count" stroke="#f97316" strokeWidth={2} dot={{ r: 3, fill: "#f97316" }} name="CVEs" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Advisories Received Timeline */}
        {advisoryTrend.length > 0 && (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-4">Advisories Received</h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={advisoryTrend}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e1e3a" />
                <XAxis dataKey="month" tick={{ fill: "#6b7280", fontSize: 11 }} />
                <YAxis tick={{ fill: "#6b7280", fontSize: 11 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#1a1a2e", border: "1px solid #2a2a4a", borderRadius: "8px" }}
                  itemStyle={{ color: "#e5e5e5" }}
                />
                <Bar dataKey="count" fill="#00d4ff" radius={[4, 4, 0, 0]} name="Advisories" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Product inventory */}
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
        <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">Your Product Inventory</h3>
        {product_inventory.length === 0 ? (
          <p className="text-gray-600 text-xs">No products in your inventory yet.</p>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {product_inventory.map((p, i) => (
              <div key={i} className="bg-[#0d0d1a] border border-[#1e1e36] rounded px-3 py-2 text-xs">
                <p className="text-gray-300 font-medium truncate">{p.product}</p>
                <p className="text-gray-600 text-[10px]">{p.vendor}</p>
                <p className={`font-mono mt-0.5 ${p.cve_count > 0 ? "text-red-400" : "text-green-400"}`}>
                  {p.cve_count > 0 ? `${p.cve_count} CVEs` : "No known CVEs"}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Unified Feed */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-300">Intelligence Feed</h2>
          <div className="flex gap-1">
            {[["all", "All"], ["cve", "CVEs"], ["threat", "Threats"]].map(([val, label]) => (
              <button
                key={val}
                onClick={() => setFeedFilter(val)}
                className={`px-3 py-1 text-[10px] rounded transition-colors ${
                  feedFilter === val
                    ? "bg-[#38BDF8] text-black font-semibold"
                    : "text-gray-500 hover:text-white border border-[#2a2a4a] hover:border-[#3a3a5a]"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {filteredFeed.length === 0 ? (
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-8 text-center text-gray-600 text-sm">
            No intelligence items matching your profile yet.
          </div>
        ) : (
          <div className="space-y-3">
            {filteredFeed.map((item, i) => (
              <TicketCard
                key={`${item._type}-${item.cve_id || item.id}-${i}`}
                item={item}
                type={item._type}
                onClick={() => {
                  if (item._type === "cve") navigate(`/cves`);
                  else if (item._type === "threat") navigate(`/threats`);
                }}
              />
            ))}
          </div>
        )}
      </div>

      {/* Advisory History */}
      {advisory_history.length > 0 && (
        <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5">
          <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">Advisory History</h3>
          <div className="space-y-1.5">
            {advisory_history.map((a, i) => (
              <div key={i} className="flex items-center gap-3 text-xs text-gray-400">
                <span className="text-gray-600 w-20 shrink-0">
                  {new Date(a.sent_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
                </span>
                <span className="text-[#00d4ff] font-mono">{a.identifier}</span>
                <span className="truncate flex-1">{a.title}</span>
                <span className="text-green-500 text-[10px] shrink-0">Sent</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4 text-center">
      <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">{label}</p>
      <p className="text-2xl font-bold" style={{ color }}>{value}</p>
    </div>
  );
}
