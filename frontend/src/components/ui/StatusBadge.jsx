const colors = {
  new: "bg-blue-900/40 text-blue-400 border-blue-800",
  active: "bg-green-900/40 text-green-400 border-green-800",
  acknowledged: "bg-purple-900/40 text-purple-400 border-purple-800",
  in_progress: "bg-yellow-900/40 text-yellow-400 border-yellow-800",
  resolved: "bg-gray-800/40 text-gray-400 border-gray-700",
  mitigated: "bg-teal-900/40 text-teal-400 border-teal-800",
};

export default function StatusBadge({ value, className = "" }) {
  const key = (value || "").toLowerCase();
  const display = (value || "—").replace(/_/g, " ");
  return (
    <span
      className={`inline-block text-[11px] px-2 py-0.5 rounded border font-semibold uppercase tracking-wide ${
        colors[key] || colors.new
      } ${className}`}
    >
      {display}
    </span>
  );
}
