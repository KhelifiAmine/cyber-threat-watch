/**
 * Static Recharts wrappers for the Report Editor.
 * No interactivity, no animations — purely visual representations for reports.
 */

import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, CartesianGrid,
} from "recharts";

const SEV_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
};

const SECTOR_COLORS = [
  "#2E2E38", "#38BDF8", "#0ea5e9", "#ef4444", "#f97316",
  "#22c55e", "#8b5cf6", "#eab308", "#6b7280", "#ec4899",
];

const chartTooltipStyle = {
  backgroundColor: "#1a1a2e",
  border: "1px solid #2a2a4a",
  borderRadius: "6px",
  fontSize: "11px",
  color: "#e5e7eb",
};

export function SeverityBar({ data }) {
  if (!data) return null;
  const chartData = [
    { name: "Critical", value: data.critical || 0, fill: SEV_COLORS.critical },
    { name: "High", value: data.high || 0, fill: SEV_COLORS.high },
    { name: "Medium", value: data.medium || 0, fill: SEV_COLORS.medium },
    { name: "Low", value: data.low || 0, fill: SEV_COLORS.low },
    { name: "Info", value: data.info || 0, fill: SEV_COLORS.info },
  ];

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={chartData} layout="vertical" margin={{ left: 10, right: 20 }}>
        <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="name" tick={{ fill: "#9ca3af", fontSize: 11 }} axisLine={false} tickLine={false} width={70} />
        <Tooltip contentStyle={chartTooltipStyle} cursor={false} />
        <Bar dataKey="value" isAnimationActive={false} radius={[0, 4, 4, 0]} barSize={14}>
          {chartData.map((entry, i) => (
            <Cell key={i} fill={entry.fill} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function ProductsBar({ data }) {
  if (!data || data.length === 0) return null;
  const items = data.slice(0, 10);

  return (
    <ResponsiveContainer width="100%" height={Math.max(160, items.length * 28)}>
      <BarChart data={items} layout="vertical" margin={{ left: 10, right: 20 }}>
        <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="name" tick={{ fill: "#9ca3af", fontSize: 10 }} axisLine={false} tickLine={false} width={110} />
        <Tooltip contentStyle={chartTooltipStyle} cursor={false} />
        <Bar dataKey="count" fill="#2E2E38" isAnimationActive={false} radius={[0, 4, 4, 0]} barSize={14} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function SectorsPie({ data }) {
  if (!data || data.length === 0) return null;
  const items = data.slice(0, 8);

  return (
    <div className="flex items-center gap-6">
      <ResponsiveContainer width={160} height={160}>
        <PieChart>
          <Pie
            data={items}
            dataKey="count"
            nameKey="sector"
            cx="50%"
            cy="50%"
            outerRadius={70}
            isAnimationActive={false}
            stroke="none"
          >
            {items.map((_, i) => (
              <Cell key={i} fill={SECTOR_COLORS[i % SECTOR_COLORS.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={chartTooltipStyle} />
        </PieChart>
      </ResponsiveContainer>
      <div className="text-xs space-y-1">
        {items.map((s, i) => (
          <div key={s.sector} className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-sm flex-shrink-0" style={{ background: SECTOR_COLORS[i % SECTOR_COLORS.length] }} />
            <span className="text-gray-300">{s.sector}</span>
            <span className="text-gray-500">({s.count})</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function RegionsBar({ data }) {
  if (!data || data.length === 0) return null;

  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 32)}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
        <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="region" tick={{ fill: "#9ca3af", fontSize: 10 }} axisLine={false} tickLine={false} width={110} />
        <Tooltip contentStyle={chartTooltipStyle} cursor={false} />
        <CartesianGrid strokeDasharray="3 3" stroke="#1e1e3a" horizontal={false} />
        <Bar dataKey="threat_count" stackId="a" fill="#f97316" isAnimationActive={false} barSize={14} name="Threats" />
        <Bar dataKey="news_count" stackId="a" fill="#0ea5e9" isAnimationActive={false} barSize={14} name="News" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
