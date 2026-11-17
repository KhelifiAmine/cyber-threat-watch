import { useNavigate } from "react-router-dom";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
};

export default function SeverityChart({ data }) {
  const navigate = useNavigate();
  const chartData = Object.entries(data)
    .filter(([_, value]) => value > 0)
    .map(([name, value]) => ({ name, value }));

  if (chartData.length === 0) {
    return <p className="text-gray-600 text-sm text-center py-8">No data available</p>;
  }

  const handleSliceClick = (entry) => {
    if (!entry || !entry.name) return;
    navigate(`/cves?severity=${entry.name.toUpperCase()}`);
  };

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={80}
          paddingAngle={3}
          dataKey="value"
          onClick={handleSliceClick}
          cursor="pointer"
        >
          {chartData.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] || "#6b7280"} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            backgroundColor: "#1a1a2e",
            border: "1px solid #2a2a4a",
            borderRadius: "6px",
            color: "#e0e0e0",
            fontSize: "13px",
          }}
          formatter={(value, name) => [value, name.charAt(0).toUpperCase() + name.slice(1)]}
        />
        <Legend
          formatter={(value) => (
            <span style={{ color: "#9ca3af", fontSize: "12px", textTransform: "capitalize" }}>
              {value}
            </span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
