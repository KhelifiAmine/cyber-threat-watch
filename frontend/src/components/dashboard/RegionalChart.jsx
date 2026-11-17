import { useNavigate } from "react-router-dom";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
};

function getSeverityColor(breakdown) {
  if (!breakdown) return "#6b7280";
  if (breakdown.CRITICAL > 0) return SEVERITY_COLORS.CRITICAL;
  if (breakdown.HIGH > 0) return SEVERITY_COLORS.HIGH;
  if (breakdown.MEDIUM > 0) return SEVERITY_COLORS.MEDIUM;
  if (breakdown.LOW > 0) return SEVERITY_COLORS.LOW;
  return "#6b7280";
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.[0]) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-[#1a1a2e] border border-[#2a2a4a] rounded p-2 text-xs">
      <p className="text-white font-medium mb-1">{d.region}</p>
      <p className="text-gray-400">{d.threat_count} threats | Avg risk: {d.avg_risk_score}</p>
      {d.severity_breakdown && (
        <div className="flex gap-2 mt-1">
          {Object.entries(d.severity_breakdown).map(([sev, count]) => (
            <span key={sev} style={{ color: SEVERITY_COLORS[sev] || "#6b7280" }}>
              {sev[0]}: {count}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function RegionalChart({ data }) {
  const navigate = useNavigate();

  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[200px] text-gray-600 text-sm">
        No regional data available
      </div>
    );
  }

  const handleClick = (entry) => {
    if (entry?.region) {
      navigate(`/threats?region=${encodeURIComponent(entry.region)}`);
    }
  };

  return (
    <ResponsiveContainer width="100%" height={Math.max(200, data.length * 40)}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20, top: 5, bottom: 5 }}>
        <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis
          type="category"
          dataKey="region"
          tick={{ fill: "#d1d5db", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={100}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(56,189,248,0.05)" }} />
        <Bar dataKey="threat_count" radius={[0, 4, 4, 0]} cursor="pointer" onClick={(_, idx) => handleClick(data[idx])}>
          {data.map((entry, i) => (
            <Cell key={i} fill={getSeverityColor(entry.severity_breakdown)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
