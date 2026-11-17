import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";

export default function TrendChart({ data }) {
  if (!data || data.length === 0) {
    return <p className="text-gray-600 text-sm text-center py-8">No data available</p>;
  }

  const formatted = data.map((d) => ({
    ...d,
    label: new Date(d.date + "T00:00:00").toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    }),
  }));

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={formatted}>
        <defs>
          <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#38BDF8" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="cveGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.2} />
            <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e1e3a" />
        <XAxis
          dataKey="label"
          tick={{ fill: "#6b7280", fontSize: 11 }}
          axisLine={{ stroke: "#2a2a4a" }}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: "#6b7280", fontSize: 11 }}
          axisLine={{ stroke: "#2a2a4a" }}
          tickLine={false}
          allowDecimals={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "#1a1a2e",
            border: "1px solid #2a2a4a",
            borderRadius: "6px",
            color: "#e0e0e0",
            fontSize: "12px",
          }}
        />
        <Legend
          wrapperStyle={{ fontSize: "11px", color: "#9ca3af", paddingTop: "8px" }}
        />
        <Area
          type="monotone"
          dataKey="count"
          name="Threats"
          stroke="#38BDF8"
          strokeWidth={2}
          fill="url(#threatGrad)"
        />
        <Area
          type="monotone"
          dataKey="cves"
          name="CVEs"
          stroke="#00d4ff"
          strokeWidth={2}
          fill="url(#cveGrad)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
