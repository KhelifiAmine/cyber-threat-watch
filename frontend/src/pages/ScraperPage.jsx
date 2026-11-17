import { useState, useEffect, useCallback, useRef } from "react";
import api from "../api/axios";
import { errorMessage } from "../api/errors";
import { useToast } from "../context/ToastContext";

const VENDOR_SPIDERS = ["fortiguard", "cisco", "microsoft"];
const GENERAL_SPIDERS = ["nvd", "github", "certfr", "certeu"];
const NEWS_SPIDERS = ["bleepingcomputer", "thehackernews", "darkreading", "securityweek"];
const ALL_SPIDERS = [...VENDOR_SPIDERS, ...GENERAL_SPIDERS, ...NEWS_SPIDERS];
const STORAGE_KEY = "ctw_scraper_tasks";

// ─── Helpers ──────────────────────────────────────────────

function loadTasks() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}"); }
  catch { return {}; }
}
function saveTasks(t) { localStorage.setItem(STORAGE_KEY, JSON.stringify(t)); }

function toUTC(ts) {
  if (!ts) return null;
  const iso = ts.includes("T") ? ts : ts.replace(" ", "T");
  if (iso.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(iso)) return new Date(iso);
  return new Date(iso + "Z");
}

function fmtDuration(start, end) {
  if (!start) return "—";
  const s = toUTC(start), e = end ? toUTC(end) : new Date();
  const sec = Math.floor((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function fmtCountdown(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds === 0) return "Due now";
  const m = Math.floor(seconds / 60), s = seconds % 60;
  if (m >= 60) return `${Math.floor(m / 60)}h ${m % 60}m`;
  return `${m}m ${s}s`;
}

// ─── Status badge ─────────────────────────────────────────

function RunStatusBadge({ status }) {
  const styles = {
    PENDING:  "border-yellow-700 text-yellow-400 bg-yellow-900/20",
    RUNNING:  "border-blue-600 text-blue-400 bg-blue-900/20",
    SUCCESS:  "border-green-700 text-green-400 bg-green-900/20",
    EMPTY:    "border-gray-600 text-gray-400 bg-gray-900/20",
    FAILURE:  "border-red-700 text-red-400 bg-red-900/20",
    never:    "border-gray-700 text-gray-500 bg-gray-900/20",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold uppercase ${styles[status] || styles.never}`}>
      {status === "RUNNING" && <span className="inline-block w-1.5 h-1.5 rounded-full bg-blue-400 mr-1 animate-pulse" />}
      {status}
    </span>
  );
}

// ─── Per-spider pause/resume toggle ───────────────────────

function SpiderToggle({ spiderName, enabled, disabledTtl, onToggle, isAdmin }) {
  const [loading, setLoading] = useState(false);

  const handleToggle = async () => {
    if (!isAdmin || loading) return;
    setLoading(true);
    try {
      await onToggle(spiderName, !enabled);
    } finally {
      setLoading(false);
    }
  };

  const fmtTtl = (s) => {
    if (!s) return "";
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h > 0 ? `${h}h ${m}m` : `${m}m`;
  };

  return (
    <button
      onClick={handleToggle}
      disabled={!isAdmin || loading}
      title={!isAdmin ? "Admin only" : enabled ? "Pause this spider (auto-resumes in 12h)" : `Auto-resumes in ${fmtTtl(disabledTtl)}`}
      className={`flex items-center gap-1 px-2 py-0.5 text-[10px] rounded border font-semibold transition-colors disabled:opacity-40 ${
        enabled
          ? "bg-green-900/20 border-green-700/50 text-green-400 hover:bg-red-900/20 hover:border-red-700/50 hover:text-red-400"
          : "bg-red-900/20 border-red-700/50 text-red-400 hover:bg-green-900/20 hover:border-green-700/50 hover:text-green-400"
      }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${enabled ? "bg-green-400" : "bg-red-400"}`} />
      {loading ? "..." : enabled ? "ON" : `PAUSED${disabledTtl ? ` · ${fmtTtl(disabledTtl)}` : ""}`}
    </button>
  );
}

// ─── Vendor Scrapers Section (Scheduled) ──────────────────

function VendorScheduleSection({ schedule, onTrigger, triggering, onRunAll, runningAll, onSpiderToggle, isAdmin }) {
  const [countdown, setCountdown] = useState({});

  // Init countdown from schedule data
  useEffect(() => {
    const c = {};
    schedule.forEach(s => { c[s.spider] = s.seconds_until_next; });
    setCountdown(c);
  }, [schedule]);

  // Live countdown tick
  useEffect(() => {
    const t = setInterval(() => {
      setCountdown(prev => {
        const next = { ...prev };
        Object.keys(next).forEach(k => {
          if (next[k] !== null && next[k] > 0) next[k]--;
        });
        return next;
      });
    }, 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <h2 className="text-base font-semibold text-white">Vendor Scrapers</h2>
        </div>
        <button
          onClick={() => onRunAll("vendor")}
          disabled={runningAll || Object.values(triggering).some(Boolean)}
          className="px-3 py-1.5 text-xs rounded bg-[#38BDF8]/10 border border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20 disabled:opacity-40 flex items-center gap-2"
        >
          {runningAll && <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8] animate-pulse" />}
          {runningAll ? "Running..." : "Run All Vendor"}
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {VENDOR_SPIDERS.map(name => {
          const info = schedule.find(s => s.spider === name);
          const isBusy = triggering[name];
          const secs = countdown[name];

          return (
            <div key={name} className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-white text-sm font-mono uppercase font-semibold">{name}</span>
                <div className="flex items-center gap-1.5">
                  <SpiderToggle
                    spiderName={name}
                    enabled={info?.enabled !== false}
                    disabledTtl={info?.disabled_ttl_seconds}
                    onToggle={onSpiderToggle}
                    isAdmin={isAdmin}
                  />
                  <button
                    onClick={() => onTrigger(name)}
                    disabled={isBusy}
                    className="px-2 py-1 text-[11px] rounded border border-[#2a2a4a] text-gray-400 hover:text-[#38BDF8] hover:border-[#38BDF8]/40 disabled:opacity-40"
                  >
                    {isBusy ? "..." : "Run"}
                  </button>
                </div>
              </div>

              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-gray-600">Interval</span>
                  <span className="text-gray-400">{info?.interval_label || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Last run</span>
                  <RunStatusBadge status={info?.last_status || "never"} />
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-600">Next in</span>
                  <span className={`font-mono font-semibold ${secs !== null && secs <= 120 ? "text-[#38BDF8]" : "text-gray-300"}`}>
                    {info?.enabled === false ? "Paused" : secs !== null && secs !== undefined ? fmtCountdown(secs) : "unknown"}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── General Scrapers Section (Manual Only) ───────────────

function GeneralScrapersSection({ schedule, onTrigger, triggering, onRunAll, runningAll }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <h2 className="text-base font-semibold text-white">General Scrapers</h2>
          <span className="text-[10px] px-2 py-0.5 rounded border border-gray-700 text-gray-500 bg-gray-900/20 font-semibold">
            Manual only — run on demand
          </span>
        </div>
        <button
          onClick={() => onRunAll("general")}
          disabled={runningAll || Object.values(triggering).some(Boolean)}
          className="px-3 py-1.5 text-xs rounded bg-[#38BDF8]/10 border border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20 disabled:opacity-40 flex items-center gap-2"
        >
          {runningAll && <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8] animate-pulse" />}
          {runningAll ? "Running..." : "Run All General"}
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {GENERAL_SPIDERS.map(name => {
          const info = schedule.find(s => s.spider === name);
          const isBusy = triggering[name];

          return (
            <div key={name} className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-white text-sm font-mono uppercase font-semibold">{name}</span>
                <button
                  onClick={() => onTrigger(name)}
                  disabled={isBusy}
                  className="px-2 py-1 text-[11px] rounded border border-[#2a2a4a] text-gray-400 hover:text-[#38BDF8] hover:border-[#38BDF8]/40 disabled:opacity-40"
                >
                  {isBusy ? "..." : "Run"}
                </button>
              </div>

              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-gray-600">Last run</span>
                  <RunStatusBadge status={info?.last_status || "never"} />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── News Scrapers Section ───────────────────────────────

const NEWS_DISPLAY_NAMES = {
  bleepingcomputer: "BleepingComp",
  thehackernews: "HackerNews",
  darkreading: "DarkReading",
  securityweek: "SecurityWeek",
};

function NewsScrapersSection({ schedule, onTrigger, triggering, onRunAll, runningAll, onSpiderToggle, isAdmin }) {
  const [countdown, setCountdown] = useState({});

  useEffect(() => {
    const c = {};
    schedule.forEach(s => { c[s.spider] = s.seconds_until_next; });
    setCountdown(c);
  }, [schedule]);

  useEffect(() => {
    const t = setInterval(() => {
      setCountdown(prev => {
        const next = { ...prev };
        Object.keys(next).forEach(k => { if (next[k] !== null && next[k] > 0) next[k]--; });
        return next;
      });
    }, 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <h2 className="text-base font-semibold text-white">News Scrapers</h2>
          <span className="text-[10px] px-2 py-0.5 rounded border border-blue-700 text-blue-400 bg-blue-900/20 font-semibold">
            Scheduled every 2h
          </span>
        </div>
        <button
          onClick={() => onRunAll("news")}
          disabled={runningAll || Object.values(triggering).some(Boolean)}
          className="px-3 py-1.5 text-xs rounded bg-[#38BDF8]/10 border border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20 disabled:opacity-40 flex items-center gap-2"
        >
          {runningAll && <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8] animate-pulse" />}
          {runningAll ? "Running..." : "Run All News"}
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {NEWS_SPIDERS.map(name => {
          const info = schedule.find(s => s.spider === name);
          const isBusy = triggering[name];
          const secs = countdown[name];

          return (
            <div key={name} className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-white text-sm font-mono uppercase font-semibold">
                  {NEWS_DISPLAY_NAMES[name] || name}
                </span>
                <div className="flex items-center gap-1.5">
                  <SpiderToggle
                    spiderName={name}
                    enabled={info?.enabled !== false}
                    disabledTtl={info?.disabled_ttl_seconds}
                    onToggle={onSpiderToggle}
                    isAdmin={isAdmin}
                  />
                  <button
                    onClick={() => onTrigger(name)}
                    disabled={isBusy}
                    className="px-2 py-1 text-[11px] rounded border border-[#2a2a4a] text-gray-400 hover:text-[#38BDF8] hover:border-[#38BDF8]/40 disabled:opacity-40"
                  >
                    {isBusy ? "..." : "Run"}
                  </button>
                </div>
              </div>

              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-gray-600">Last run</span>
                  <RunStatusBadge status={info?.last_status || "never"} />
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-600">Next in</span>
                  <span className={`font-mono font-semibold ${secs !== null && secs <= 120 ? "text-[#38BDF8]" : "text-gray-300"}`}>
                    {info?.enabled === false ? "Paused" : secs !== null && secs !== undefined ? fmtCountdown(secs) : "unknown"}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Run History ──────────────────────────────────────────

function RunHistory({ onSelectRun, selectedTaskId, refresh }) {
  const [runs, setRuns] = useState([]);

  const fetchRuns = useCallback(async () => {
    try {
      const res = await api.get("/api/scraper/runs?limit=50");
      setRuns(res.data);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchRuns(); }, [fetchRuns, refresh]);

  // Auto-refresh while any run is RUNNING
  useEffect(() => {
    const hasActive = runs.some(r => r.status === "RUNNING" || r.status === "PENDING" || r.status === "SKIPPED");
    if (!hasActive) return;
    const t = setInterval(fetchRuns, 3000);
    return () => clearInterval(t);
  }, [runs, fetchRuns]);

  return (
    <div>
      <h2 className="text-base font-semibold text-white mb-3">Run History</h2>
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#2a2a4a] text-gray-500 uppercase">
              <th className="text-left px-4 py-2.5 font-medium">Spider</th>
              <th className="text-left px-4 py-2.5 font-medium">Status</th>
              <th className="text-left px-4 py-2.5 font-medium">Started</th>
              <th className="text-left px-4 py-2.5 font-medium w-16">Duration</th>
              <th className="text-left px-4 py-2.5 font-medium w-16">Scraped</th>
              <th className="text-left px-4 py-2.5 font-medium w-12">New</th>
              <th className="text-left px-4 py-2.5 font-medium w-16">Dupes</th>
              <th className="text-left px-4 py-2.5 font-medium w-16 text-red-500">Dropped</th>
              <th className="text-left px-4 py-2.5 font-medium w-16 text-[#38BDF8]">Alerts</th>
              <th className="text-left px-4 py-2.5 font-medium">By</th>
            </tr>
          </thead>
          <tbody>
            {runs.length === 0 ? (
              <tr><td colSpan={10} className="px-4 py-6 text-center text-gray-600">No runs yet. Trigger a spider to see history.</td></tr>
            ) : runs.map(run => (
              <tr
                key={run.id}
                onClick={() => onSelectRun(run.task_id === selectedTaskId ? null : run.task_id)}
                className={`border-b border-[#1e1e3a] cursor-pointer transition-colors ${run.task_id === selectedTaskId ? "bg-[#1e1e3a]" : "hover:bg-[#161628]"}`}
              >
                <td className="px-4 py-2.5 font-mono text-white uppercase">{run.spider_name}</td>
                <td className="px-4 py-2.5"><RunStatusBadge status={run.status} /></td>
                <td className="px-4 py-2.5 text-gray-400">
                  {run.started_at ? toUTC(run.started_at).toLocaleTimeString() : "—"}
                  <span className="text-gray-600 ml-1">{run.started_at ? toUTC(run.started_at).toLocaleDateString() : ""}</span>
                </td>
                <td className="px-4 py-2.5 text-gray-300 font-mono">{fmtDuration(run.started_at, run.finished_at)}</td>
                <td className="px-4 py-2.5 text-gray-300">{run.items_scraped}</td>
                <td className="px-4 py-2.5 text-green-400 font-semibold">{run.items_new}</td>
                <td className="px-4 py-2.5 text-gray-500">{run.items_duplicate}</td>
                <td className="px-4 py-2.5 text-red-400">{run.items_dropped_nlp + run.items_dropped_clean}</td>
                <td className="px-4 py-2.5 text-[#38BDF8] font-semibold">{run.alerts_created}</td>
                <td className="px-4 py-2.5 text-gray-500 truncate max-w-[100px]">{run.triggered_by}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Live Log Terminal ────────────────────────────────────

function LogTerminal({ taskId, onClose }) {
  const [lines, setLines] = useState([]);
  const [done, setDone] = useState(false);
  const logRef = useRef(null);

  useEffect(() => {
    if (!taskId) return;
    setLines([]);
    setDone(false);

    const controller = new AbortController();
    const token = localStorage.getItem("access_token");
    const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";

    (async () => {
      try {
        const response = await fetch(`${API_BASE}/api/scraper/logs/${taskId}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });

        if (!response.ok || !response.body) {
          setDone(true);
          return;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done: streamDone, value } = await reader.read();
          if (streamDone) { setDone(true); break; }

          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split("\n\n");
          buffer = parts.pop();

          for (const part of parts) {
            const line = part.trim();
            if (!line.startsWith("data: ")) continue;
            const data = line.slice(6);
            if (data === "__DONE__") { setDone(true); return; }
            if (data) setLines(prev => [...prev, data]);
          }
        }
      } catch (err) {
        if (err.name !== "AbortError") setDone(true);
      }
    })();

    return () => controller.abort();
  }, [taskId]);

  // Auto-scroll inside the log panel only
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  const lineColor = (line) => {
    if (line.includes("DROPPED") || line.includes("ERROR")) return "text-red-400";
    if (line.includes("VERIFIED")) return "text-green-400";
    if (line.includes("LOW-CONF")) return "text-orange-400";
    if (line.includes("ALERT")) return "text-[#38BDF8]";
    if (line.includes("DONE")) return "text-blue-400 font-semibold";
    if (line.includes("WARNING")) return "text-yellow-500";
    return "text-gray-300";
  };

  return (
    <div className="bg-[#0a0a12] border border-[#2a2a4a] rounded-lg">
      <div className="flex items-center justify-between px-4 py-2 border-b border-[#2a2a4a]">
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500 font-mono">task: {taskId?.slice(0, 16)}...</span>
          {!done && <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />}
          {done && <span className="text-xs text-green-400">Done</span>}
        </div>
        <button onClick={onClose} className="text-gray-600 hover:text-gray-300 text-sm">&times;</button>
      </div>
      <div ref={logRef} className="h-72 overflow-y-auto p-4 font-mono text-xs space-y-0.5">
        {lines.length === 0 && !done && (
          <span className="text-gray-600 animate-pulse">Waiting for output...</span>
        )}
        {lines.map((line, i) => (
          <div key={i} className={lineColor(line)}>{line}</div>
        ))}
        {done && lines.length > 0 && (
          <div className="text-blue-400 mt-2">— Spider finished —</div>
        )}
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────

export default function ScraperPage() {
  const { addToast } = useToast();
  const [triggering, setTriggering] = useState({});
  const [runningVendor, setRunningVendor] = useState(false);
  const [runningGeneral, setRunningGeneral] = useState(false);
  const [runningNews, setRunningNews] = useState(false);
  const [tasks, setTasks] = useState(loadTasks);
  const [selectedTaskId, setSelectedTaskId] = useState(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [vendorSchedule, setVendorSchedule] = useState([]);
  const [generalSchedule, setGeneralSchedule] = useState([]);
  const [newsSchedule, setNewsSchedule] = useState([]);

  // Detect admin role from JWT
  const isAdmin = (() => {
    try {
      const token = localStorage.getItem("access_token");
      if (!token) return false;
      const payload = JSON.parse(atob(token.split(".")[1]));
      return payload.role?.toLowerCase() === "admin";
    } catch { return false; }
  })();

  useEffect(() => { saveTasks(tasks); }, [tasks]);

  // Fetch schedule data
  const fetchSchedule = useCallback(async () => {
    try {
      const res = await api.get("/api/scraper/schedule");
      setVendorSchedule(res.data.vendor_spiders || []);
      setGeneralSchedule(res.data.general_spiders || []);
      setNewsSchedule(res.data.news_spiders || []);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchSchedule(); }, [fetchSchedule]);

  // Auto-refresh schedule every 30s so countdowns reset after spiders fire
  useEffect(() => {
    const t = setInterval(fetchSchedule, 30000);
    return () => clearInterval(t);
  }, [fetchSchedule]);

  const triggerSpider = async (name) => {
    if (triggering[name]) return;
    setTriggering(t => ({ ...t, [name]: true }));
    try {
      const res = await api.post(`/api/scraper/run/${name}`);
      const tid = res.data.task_id;
      setTasks(prev => ({
        ...prev,
        [name]: { spider: name, task_id: tid, status: "PENDING", startedAt: new Date().toISOString() }
      }));
      setSelectedTaskId(tid);
      setHistoryRefresh(r => r + 1);
      // Refresh schedule so countdown resets
      fetchSchedule();
    } catch (err) {
      addToast(errorMessage(err, `Failed to trigger ${name}`), "error");
    } finally {
      setTriggering(t => ({ ...t, [name]: false }));
    }
  };

  const toggleSpider = async (spiderName, enable) => {
    try {
      const res = await api.post(`/api/scraper/schedule/spider/${spiderName}/enabled`, { enabled: enable });
      addToast(
        enable ? `${spiderName} resumed` : `${spiderName} paused — auto-resumes in 12h`,
        enable ? "success" : "info"
      );
      // Refresh schedule to reflect new state
      await fetchSchedule();
    } catch (err) {
      addToast(errorMessage(err, `Failed to toggle ${spiderName}`), "error");
    }
  };

  const runAllGroup = async (group) => {
    const setters = { vendor: [runningVendor, setRunningVendor], general: [runningGeneral, setRunningGeneral], news: [runningNews, setRunningNews] };
    const [running, setRunning] = setters[group] || setters.general;
    if (running) return;
    setRunning(true);
    try {
      const res = await api.post(`/api/scraper/run?group=${group}`);
      const tid = res.data.tasks?.[0]?.task_id;
      addToast(`All ${group} spiders queued — running one at a time.`, "success");
      if (tid) setSelectedTaskId(tid);
      setHistoryRefresh(r => r + 1);
    } catch (err) {
      addToast(errorMessage(err, `Failed to start ${group} run.`), "error");
    }
    setTimeout(() => setRunning(false), 5000);
  };

  return (
    <div className="space-y-8" style={{ overflowAnchor: "none" }}>
      <h1 className="text-xl font-bold text-white">Scrapers</h1>

      {/* Vendor Scrapers — scheduled */}
      <VendorScheduleSection
        schedule={vendorSchedule}
        onTrigger={triggerSpider}
        triggering={triggering}
        onRunAll={runAllGroup}
        runningAll={runningVendor}
        onSpiderToggle={toggleSpider}
        isAdmin={isAdmin}
      />

      {/* General Scrapers — manual only */}
      <GeneralScrapersSection
        schedule={generalSchedule}
        onTrigger={triggerSpider}
        triggering={triggering}
        onRunAll={runAllGroup}
        runningAll={runningGeneral}
      />

      {/* News Scrapers */}
      <NewsScrapersSection
        schedule={newsSchedule}
        onTrigger={triggerSpider}
        triggering={triggering}
        onRunAll={runAllGroup}
        runningAll={runningNews}
        onSpiderToggle={toggleSpider}
        isAdmin={isAdmin}
      />

      {/* Live log terminal */}
      {selectedTaskId && (
        <div>
          <h2 className="text-base font-semibold text-white mb-3">Live Output</h2>
          <LogTerminal taskId={selectedTaskId} onClose={() => setSelectedTaskId(null)} />
        </div>
      )}

      {/* Run history */}
      <RunHistory
        onSelectRun={setSelectedTaskId}
        selectedTaskId={selectedTaskId}
        refresh={historyRefresh}
      />
    </div>
  );
}
