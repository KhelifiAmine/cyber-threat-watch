const colors = {
  critical: "bg-red-900/40 text-red-400 border-red-800",
  high: "bg-orange-900/40 text-orange-400 border-orange-800",
  medium: "bg-yellow-900/40 text-yellow-400 border-yellow-800",
  low: "bg-green-900/40 text-green-400 border-green-800",
  info: "bg-gray-800/40 text-gray-400 border-gray-700",
  urgent: "bg-red-900/50 text-red-300 border-red-700",
};

export default function SeverityBadge({ value, className = "" }) {
  const key = (value || "").toLowerCase();
  return (
    <span
      className={`inline-block text-[11px] px-2 py-0.5 rounded border font-semibold uppercase tracking-wide ${
        colors[key] || colors.info
      } ${className}`}
    >
      {value || "—"}
    </span>
  );
}
