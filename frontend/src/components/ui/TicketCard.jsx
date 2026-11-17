const SEV_COLORS = {
  CRITICAL: "#ef4444", critical: "#ef4444",
  HIGH: "#f97316", high: "#f97316",
  MEDIUM: "#eab308", medium: "#eab308",
  LOW: "#22c55e", low: "#22c55e",
  INFO: "#6b7280", info: "#6b7280",
};

const TYPE_BADGE = {
  cve: { label: "CVE", bg: "bg-blue-500/10", text: "text-blue-400" },
  threat: { label: "Threat", bg: "bg-orange-500/10", text: "text-orange-400" },
  news: { label: "News", bg: "bg-purple-500/10", text: "text-purple-400" },
};

function relTime(isoStr) {
  if (!isoStr) return "";
  const diff = Date.now() - new Date(isoStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function TicketCard({ item, type, onClick }) {
  const badge = TYPE_BADGE[type] || TYPE_BADGE.cve;
  const severity = item.severity || item.cvss_severity || "";
  const sevColor = SEV_COLORS[severity?.toLowerCase()] || "#6b7280";
  const title = item.title || item.cve_id || "Untitled";
  const description = item.description || item.summary || "";
  const source = item.source || "";
  const date = item.created_at || item.published_at || "";
  const sentAt = item.advisory_sent_at || item.sent_at;
  const score = item.cvss_base_score || item.risk_score;
  const identifier = item.cve_id || "";

  return (
    <div
      onClick={onClick}
      className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4 hover:border-[#3a3a5a] transition-colors cursor-pointer"
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${badge.bg} ${badge.text}`}>
            {badge.label}
          </span>
          {severity && (
            <span className="text-[10px] font-medium px-1.5 py-0.5 rounded" style={{ color: sevColor, background: sevColor + "15" }}>
              {severity.toUpperCase()}
            </span>
          )}
          {sentAt ? (
            <span className="text-[10px] text-green-400">Sent</span>
          ) : (
            <span className="text-[10px] text-gray-600">Pending</span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {score != null && (
            <span className="text-xs font-mono font-bold" style={{ color: sevColor }}>{typeof score === "number" ? score.toFixed(1) : score}</span>
          )}
          <span className="text-[10px] text-gray-600">{relTime(date)}</span>
        </div>
      </div>

      <h3 className="text-sm text-gray-200 font-medium mb-1 line-clamp-2">
        {identifier && <span className="text-[#00d4ff] font-mono mr-2">{identifier}</span>}
        {title}
      </h3>

      {description && (
        <p className="text-xs text-gray-500 line-clamp-2 mb-2">{description.slice(0, 200)}</p>
      )}

      {source && (
        <span className="text-[10px] text-gray-600">{source}</span>
      )}
    </div>
  );
}
