import { useState, useEffect, useCallback, Fragment } from "react";
import api from "../api/axios";
import Pagination from "../components/ui/Pagination";
import SearchBar from "../components/ui/SearchBar";
import FilterSelect from "../components/ui/FilterSelect";

const ACTION_OPTIONS = [
  // Auth / Users
  { value: "LOGIN",                  label: "Login" },
  { value: "CREATE_USER",            label: "Create User" },
  { value: "UPDATE_USER",            label: "Update User" },
  { value: "DELETE_USER",            label: "Delete User" },
  // Content edits
  { value: "EDIT_CVE",               label: "Edit CVE" },
  { value: "EDIT_THREAT",            label: "Edit Threat" },
  { value: "EDIT_NEWS",              label: "Edit News" },
  { value: "FLAG_NEWS",              label: "Flag News" },
  { value: "MANUAL_FLAG_CVE",        label: "Flag CVE" },
  { value: "MANUAL_FLAG_THREAT",     label: "Flag Threat" },
  // Proposals
  { value: "APPROVE_CVE_PROPOSAL",   label: "Approve CVE Proposal" },
  { value: "APPROVE_THREAT_PROPOSAL",label: "Approve Threat Proposal" },
  { value: "APPROVE_NEWS_PROPOSAL",  label: "Approve News Proposal" },
  { value: "CLOSE_CVE_PROPOSAL",     label: "Close CVE Proposal" },
  { value: "CLOSE_THREAT_PROPOSAL",  label: "Close Threat Proposal" },
  { value: "REJECT_NEWS_PROPOSAL",   label: "Reject News Proposal" },
  // Advisories
  { value: "SEND_CVE_ADVISORY",      label: "Send CVE Advisory" },
  { value: "SEND_THREAT_ADVISORY",   label: "Send Threat Advisory" },
  { value: "SEND_NEWS_ADVISORY",     label: "Send News Advisory" },
  { value: "SEND_DIRECT_ADVISORY",   label: "Send Direct Advisory" },
  { value: "TRANSLATE_CONTENT",      label: "Translate Content" },
  // Scraper / Schedule
  { value: "RUN_SPIDER",             label: "Run Spider" },
  { value: "RUN_ALL_SPIDERS",        label: "Run All Spiders" },
  { value: "TOGGLE_SCHEDULE",        label: "Toggle Schedule" },
  { value: "TOGGLE_SPIDER",          label: "Toggle Spider" },
  // Clients
  { value: "ADD_CLIENT",             label: "Add Client" },
  { value: "EDIT_CLIENT",            label: "Edit Client" },
  { value: "DELETE_CLIENT",          label: "Delete Client" },
  { value: "IMPORT_CLIENTS_PREVIEW", label: "Import Clients (Preview)" },
  { value: "IMPORT_CLIENTS_CONFIRM", label: "Import Clients (Confirm)" },
];

const RESOURCE_OPTIONS = [
  { value: "user",                    label: "User" },
  { value: "cve",                     label: "CVE" },
  { value: "cve_proposal",            label: "CVE Proposal" },
  { value: "threat",                  label: "Threat" },
  { value: "threat_proposal",         label: "Threat Proposal" },
  { value: "news",                    label: "News" },
  { value: "news_proposal",           label: "News Proposal" },
  { value: "scraper",                 label: "Scraper" },
  { value: "advisory",                label: "Advisory" },
  { value: "client",                  label: "Client" },
  { value: "notification_recipients", label: "Client Recipients" },
];

const ACTION_COLORS = {
  LOGIN:                   "text-blue-400",
  CREATE_USER:             "text-blue-300",
  UPDATE_USER:             "text-yellow-400",
  DELETE_USER:             "text-red-400",
  EDIT_CVE:                "text-cyan-400",
  EDIT_THREAT:             "text-cyan-400",
  EDIT_NEWS:               "text-cyan-400",
  FLAG_NEWS:               "text-yellow-400",
  MANUAL_FLAG_CVE:         "text-yellow-400",
  MANUAL_FLAG_THREAT:      "text-yellow-400",
  APPROVE_CVE_PROPOSAL:    "text-green-400",
  APPROVE_THREAT_PROPOSAL: "text-green-400",
  APPROVE_NEWS_PROPOSAL:   "text-green-400",
  CLOSE_CVE_PROPOSAL:      "text-gray-400",
  CLOSE_THREAT_PROPOSAL:   "text-gray-400",
  REJECT_NEWS_PROPOSAL:    "text-red-400",
  SEND_CVE_ADVISORY:       "text-purple-400",
  SEND_THREAT_ADVISORY:    "text-purple-400",
  SEND_NEWS_ADVISORY:      "text-purple-400",
  SEND_DIRECT_ADVISORY:    "text-purple-400",
  TRANSLATE_CONTENT:       "text-blue-300",
  ACKNOWLEDGE_ALERT:       "text-purple-400",
  UPDATE_ALERT:            "text-yellow-400",
  DISMISS_ALERT:           "text-red-400",
  RUN_SPIDER:              "text-green-400",
  RUN_ALL_SPIDERS:         "text-green-400",
  TOGGLE_SCHEDULE:         "text-orange-400",
  TOGGLE_SPIDER:           "text-orange-400",
  ADD_CLIENT:              "text-green-400",
  EDIT_CLIENT:             "text-cyan-400",
  DELETE_CLIENT:           "text-red-400",
  IMPORT_CLIENTS_PREVIEW:  "text-cyan-400",
  IMPORT_CLIENTS_CONFIRM:  "text-cyan-400",
};

const ROLE_COLORS = {
  admin:   "bg-red-900/30 text-red-400 border-red-800",
  analyst: "bg-blue-900/30 text-blue-400 border-blue-800",
  client:  "bg-green-900/30 text-green-400 border-green-800",
};

export default function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(0);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState({});

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, per_page: 25 };
      if (search) params.user_email = search;
      if (action) params.action = action;
      if (resourceType) params.resource_type = resourceType;
      const res = await api.get("/api/admin/logs", { params });
      setLogs(res.data.items || []);
      setTotal(res.data.total || 0);
      setPages(res.data.pages || 0);
    } catch {
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }, [page, search, action, resourceType]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const handleSearch = (val) => { setSearch(val); setPage(1); };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Audit Log</h1>
        <span className="text-gray-500 text-sm">{total} records</span>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-4">
        <div className="flex-1 min-w-[200px]">
          <SearchBar onSearch={handleSearch} placeholder="Search by user email..." />
        </div>
        <FilterSelect label="Action" value={action} onChange={(v) => { setAction(v); setPage(1); }} options={ACTION_OPTIONS} />
        <FilterSelect label="Resource" value={resourceType} onChange={(v) => { setResourceType(v); setPage(1); }} options={RESOURCE_OPTIONS} />
      </div>

      {/* Table */}
      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2a4a] text-gray-500 text-xs uppercase">
              <th className="text-left px-4 py-3 font-medium w-36">Time</th>
              <th className="text-left px-4 py-3 font-medium">User</th>
              <th className="text-left px-4 py-3 font-medium w-16">Role</th>
              <th className="text-left px-4 py-3 font-medium w-40">Action</th>
              <th className="text-left px-4 py-3 font-medium w-24">Resource</th>
              <th className="text-left px-4 py-3 font-medium">Details</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-600">Loading...</td></tr>
            ) : logs.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-600">No audit records found.</td></tr>
            ) : logs.map((log) => {
              const hasMeta = log.event_metadata && Object.keys(log.event_metadata).length > 0;
              const isOpen = !!expanded[log.id];
              return (
                <Fragment key={log.id}>
                  <tr className="border-b border-[#1e1e3a] hover:bg-[#1a1a2e] transition-colors">
                    <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                      <div>{new Date(log.timestamp).toLocaleDateString()}</div>
                      <div>{new Date(log.timestamp).toLocaleTimeString()}</div>
                    </td>
                    <td className="px-4 py-3 text-gray-300 text-xs">{log.user_email}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase ${ROLE_COLORS[log.user_role] || "text-gray-400"}`}>
                        {log.user_role}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-mono font-semibold ${ACTION_COLORS[log.action] || "text-gray-400"}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {log.resource_type && (
                        <span className="font-mono">
                          {log.resource_type}{log.resource_id ? `#${log.resource_id}` : ""}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="flex-1">{log.details || "—"}</span>
                        {hasMeta && (
                          <button
                            onClick={() => setExpanded((e) => ({ ...e, [log.id]: !e[log.id] }))}
                            className="text-[10px] px-2 py-0.5 rounded border border-[#2a2a4a] text-[#00d4ff] hover:bg-[#1a1a2e]"
                          >
                            {isOpen ? "Hide" : "Metadata"}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                  {hasMeta && isOpen && (
                    <tr className="border-b border-[#1e1e3a] bg-[#0f0f23]">
                      <td colSpan={6} className="px-4 py-3">
                        <pre className="text-[11px] text-gray-400 font-mono whitespace-pre-wrap break-words">
                          {JSON.stringify(log.event_metadata, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      <Pagination page={page} pages={pages} onPageChange={setPage} />
    </div>
  );
}
