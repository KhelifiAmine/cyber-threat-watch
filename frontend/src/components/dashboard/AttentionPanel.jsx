import { Link } from "react-router-dom";

function relTime(isoStr) {
  if (!isoStr) return "";
  const diff = Date.now() - new Date(isoStr).getTime();
  const h = Math.floor(diff / 3600000);
  if (h < 1) return "< 1h ago";
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function CvssBadge({ score }) {
  if (score == null) return null;
  const color = score >= 9 ? "text-red-400" : score >= 7 ? "text-orange-400" : "text-yellow-400";
  return <span className={`text-xs font-mono font-bold ${color}`}>{score.toFixed(1)}</span>;
}

export default function AttentionPanel({ data }) {
  if (!data) return null;

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {/* Unsent High-Risk */}
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4">
        <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">Unsent High-Risk</h3>
        {data.unsent_cves?.length > 0 ? (
          <ul className="space-y-2">
            {data.unsent_cves.map((c) => (
              <li key={c.cve_id}>
                <Link
                  to={`/cves?cve_id=${c.cve_id}`}
                  className="flex items-center justify-between text-sm hover:text-[#38BDF8] text-gray-300"
                >
                  <span className="truncate mr-2">{c.cve_id}</span>
                  <span className="flex items-center gap-2 shrink-0">
                    <CvssBadge score={c.cvss} />
                    <span className="text-[10px] text-gray-600">{relTime(c.created_at)}</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-gray-600">No unsent high-risk items</p>
        )}
        {data.unsent_threats?.length > 0 && (
          <>
            <hr className="border-[#2a2a4a] my-2" />
            <ul className="space-y-2">
              {data.unsent_threats.slice(0, 3).map((t) => (
                <li key={t.id}>
                  <Link
                    to={`/threats`}
                    className="flex items-center justify-between text-sm hover:text-[#38BDF8] text-gray-300"
                  >
                    <span className="truncate mr-2">{t.title?.slice(0, 40)}</span>
                    <span className="text-xs text-orange-400 font-mono shrink-0">{t.risk_score}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>

      {/* Pending Review */}
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4 flex flex-col items-center justify-center">
        <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">Pending Review</h3>
        <p className="text-3xl font-bold text-[#38BDF8] mb-3">{data.pending_review_count || 0}</p>
        <Link
          to="/review"
          className="px-4 py-1.5 text-xs rounded bg-[#1a1a2e] border border-[#2a2a4a] text-gray-300 hover:text-white hover:border-[#38BDF8]/40"
        >
          Go to Queue
        </Link>
      </div>

      {/* Spider Alerts */}
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4">
        <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">Spider Alerts</h3>
        {data.failed_spiders?.length > 0 ? (
          <ul className="space-y-2">
            {data.failed_spiders.map((f, i) => (
              <li key={i} className="text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-red-400 font-medium">{f.name}</span>
                  <span className="text-[10px] text-gray-600">{relTime(f.failed_at)}</span>
                </div>
                {f.last_error && (
                  <p className="text-[10px] text-gray-600 truncate mt-0.5">{f.last_error}</p>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-gray-600">No failures in last 24h</p>
        )}
      </div>
    </div>
  );
}
