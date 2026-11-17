import { useState, useEffect } from "react";

export default function Pagination({ page, pages, onPageChange }) {
  const [jumpValue, setJumpValue] = useState("");

  useEffect(() => {
    setJumpValue("");
  }, [page]);

  if (pages <= 1) return null;

  const range = [];
  const start = Math.max(1, page - 2);
  const end = Math.min(pages, page + 2);
  for (let i = start; i <= end; i++) range.push(i);

  const go = (p) => {
    const n = Math.min(pages, Math.max(1, Number(p) || 1));
    onPageChange(n);
  };

  const submitJump = (e) => {
    e.preventDefault();
    if (jumpValue) go(jumpValue);
  };

  const btn = "px-3 py-1.5 text-xs rounded bg-[#1a1a2e] border border-[#2a2a4a] text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed";

  return (
    <div className="flex flex-wrap items-center gap-1 mt-4">
      <button onClick={() => go(1)} disabled={page <= 1} className={btn}>« First</button>
      <button onClick={() => go(page - 1)} disabled={page <= 1} className={btn}>Prev</button>

      {start > 1 && <span className="text-gray-600 text-xs px-1">...</span>}
      {range.map((p) => (
        <button
          key={p}
          onClick={() => go(p)}
          className={`px-3 py-1.5 text-xs rounded border ${
            p === page
              ? "bg-[#38BDF8]/10 border-[#38BDF8]/40 text-[#38BDF8]"
              : "bg-[#1a1a2e] border-[#2a2a4a] text-gray-400 hover:text-white"
          }`}
        >
          {p}
        </button>
      ))}
      {end < pages && <span className="text-gray-600 text-xs px-1">...</span>}

      <button onClick={() => go(page + 1)} disabled={page >= pages} className={btn}>Next</button>
      <button onClick={() => go(pages)} disabled={page >= pages} className={btn}>Last »</button>

      <span className="text-gray-500 text-xs ml-3">
        Page <span className="text-gray-200 font-semibold">{page}</span> of{" "}
        <span className="text-gray-200 font-semibold">{pages}</span>
      </span>

      <form onSubmit={submitJump} className="flex items-center gap-1 ml-3">
        <label className="text-gray-500 text-xs">Jump to</label>
        <input
          type="number"
          min="1"
          max={pages}
          value={jumpValue}
          onChange={(e) => setJumpValue(e.target.value)}
          placeholder="#"
          className="w-14 px-2 py-1 text-xs rounded bg-[#1a1a2e] border border-[#2a2a4a] text-gray-200 focus:outline-none focus:border-[#38BDF8]/50"
        />
        <button type="submit" className={btn}>Go</button>
      </form>
    </div>
  );
}
