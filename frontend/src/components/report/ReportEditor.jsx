/**
 * ReportEditor — Full-screen overlay for editing and exporting reports.
 * Single-pane editable view with static charts and PDF export.
 */

import { useState, useCallback } from "react";
import { createPortal } from "react-dom";
import api from "../../api/axios";
import { errorMessage } from "../../api/errors";
import { useToast } from "../../context/ToastContext";
import { SeverityBar, ProductsBar, SectorsPie, RegionsBar } from "./ReportCharts";

const SEV_COLORS = {
  CRITICAL: "text-red-400 bg-red-900/20 border-red-800",
  HIGH: "text-orange-400 bg-orange-900/20 border-orange-800",
  MEDIUM: "text-yellow-400 bg-yellow-900/20 border-yellow-800",
  LOW: "text-green-400 bg-green-900/20 border-green-800",
};

function SectionTitle({ children }) {
  return (
    <h3 className="text-[10px] font-bold uppercase tracking-wider text-gray-500 mb-3 pb-1 border-b border-[#38BDF8]/30 inline-block">
      {children}
    </h3>
  );
}

function EditableText({ value, onChange, placeholder, multiline, className = "" }) {
  if (multiline) {
    return (
      <textarea
        value={value || ""}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full bg-transparent border border-[#2a2a4a] rounded px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-[#38BDF8]/50 resize-y min-h-[80px] ${className}`}
        rows={4}
      />
    );
  }
  return (
    <input
      type="text"
      value={value || ""}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={`bg-transparent border border-[#2a2a4a] rounded px-2 py-1 text-gray-200 text-sm focus:outline-none focus:border-[#38BDF8]/50 ${className}`}
    />
  );
}

function KpiCard({ label, value, onChange }) {
  return (
    <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-3 text-center flex-1 min-w-[100px]">
      <input
        type="text"
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        className="w-full text-center bg-transparent text-2xl font-bold text-white focus:outline-none focus:text-[#38BDF8]"
      />
      <div className="text-[9px] text-gray-500 uppercase tracking-wider mt-1">{label}</div>
    </div>
  );
}

function DataTable({ columns, rows, editable, onCellEdit }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-[#2a2a4a]">
            {columns.map((col) => (
              <th key={col.key} className="text-left px-2 py-1.5 text-gray-500 font-semibold text-[10px] uppercase tracking-wider">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {(rows || []).map((row, ri) => (
            <tr key={ri} className="border-b border-[#1e1e3a] hover:bg-[#161628]">
              {columns.map((col) => (
                <td key={col.key} className="px-2 py-1.5 text-gray-300">
                  {editable && col.editable ? (
                    <input
                      type="text"
                      value={row[col.key] ?? ""}
                      onChange={(e) => onCellEdit(ri, col.key, e.target.value)}
                      className="bg-transparent border-b border-transparent hover:border-[#2a2a4a] focus:border-[#38BDF8]/50 focus:outline-none w-full text-xs text-gray-300"
                    />
                  ) : col.render ? (
                    col.render(row[col.key], row)
                  ) : (
                    row[col.key] ?? "—"
                  )}
                </td>
              ))}
            </tr>
          ))}
          {(!rows || rows.length === 0) && (
            <tr><td colSpan={columns.length} className="px-2 py-4 text-center text-gray-600 italic">No data</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function SevBadge({ severity }) {
  const s = (severity || "").toUpperCase();
  const cls = SEV_COLORS[s] || "text-gray-400 bg-gray-800/20 border-gray-700";
  return <span className={`text-[9px] font-semibold px-1.5 py-0.5 rounded border ${cls}`}>{s || "—"}</span>;
}


export default function ReportEditor({ reportType, data, onClose }) {
  const [form, setForm] = useState(() => ({
    ...data,
    executive_summary: data.executive_summary || "",
    severity_commentary: data.severity_commentary || "",
    products_commentary: data.products_commentary || "",
    sectors_commentary: data.sectors_commentary || "",
    regions_commentary: data.regions_commentary || "",
  }));
  const [exporting, setExporting] = useState(false);
  const { addToast } = useToast();

  const update = useCallback((key, val) => {
    setForm((prev) => ({ ...prev, [key]: val }));
  }, []);

  const updateOverview = useCallback((key, val) => {
    setForm((prev) => ({
      ...prev,
      overview: { ...prev.overview, [key]: val },
    }));
  }, []);

  const updateCveCell = useCallback((ri, key, val) => {
    setForm((prev) => {
      const cves = [...(prev.client_data?.cve_exposure || prev.cves || [])];
      cves[ri] = { ...cves[ri], [key]: val };
      if (prev.client_data) {
        return { ...prev, client_data: { ...prev.client_data, cve_exposure: cves } };
      }
      return { ...prev, cves };
    });
  }, []);

  const updateExposureCell = useCallback((ri, key, val) => {
    setForm((prev) => {
      const exposure = [...(prev.exposure || [])];
      exposure[ri] = { ...exposure[ri], [key]: val };
      return { ...prev, exposure };
    });
  }, []);

  const handleExportPdf = async () => {
    setExporting(true);
    try {
      const res = await api.post("/api/reports/export-pdf", form, {
        responseType: "blob",
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `CTW_${(reportType || "general").replace(/^\w/, c => c.toUpperCase())}_Report_${new Date().toISOString().slice(0, 10).replace(/-/g, "")}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      addToast("PDF exported successfully.", "success");
    } catch (err) {
      addToast(errorMessage(err, "Failed to export PDF."), "error");
    } finally {
      setExporting(false);
    }
  };

  const isClient = reportType === "client";
  const clientData = form.client_data;

  return createPortal(
    <div className="fixed inset-0 bg-[#0a0a15] flex flex-col" style={{ zIndex: 9999 }}>
      {/* ── Header bar ── */}
      <div className="flex items-center justify-between px-5 py-2.5 bg-[#12121e] border-b border-[#2a2a4a] shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-[#38BDF8] font-bold text-sm tracking-wide">
            Report Editor
          </span>
          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
            isClient
              ? "text-cyan-300 bg-cyan-900/20 border-cyan-800"
              : "text-purple-300 bg-purple-900/20 border-purple-800"
          }`}>
            {isClient ? "CLIENT" : "GENERAL"}
          </span>
          <span className="text-[10px] text-gray-500">
            Last {form.days || 30} days
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportPdf}
            disabled={exporting}
            className="text-[10px] px-3 py-1.5 rounded bg-[#38BDF8] text-black font-semibold hover:bg-yellow-300 disabled:opacity-50 transition-colors"
          >
            {exporting ? "Exporting..." : "Download PDF"}
          </button>
          <button
            onClick={onClose}
            className="text-[10px] px-3 py-1.5 rounded border border-[#2a2a4a] text-gray-400 hover:text-white hover:border-[#3a3a5a] transition-colors"
          >
            Close
          </button>
        </div>
      </div>

      {/* ── Scrollable content ── */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-[900px] mx-auto py-6 px-6 space-y-6">

          {/* ── Report Header ── */}
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="text-[#38BDF8] text-lg font-bold tracking-wide mb-1">
                  Cyber Threat Watch
                </div>
                {isClient && clientData ? (
                  <div className="text-gray-400 text-xs space-y-0.5">
                    <div><strong className="text-gray-300">{clientData.client?.name}</strong> &mdash; {clientData.client?.company}</div>
                    <div>Sector: {clientData.client?.sector || "—"} &bull; Products: {clientData.client?.products_count || 0}</div>
                    {clientData.client?.regions?.length > 0 && (
                      <div className="flex items-center gap-1 mt-1">
                        {clientData.client.regions.map((r) => (
                          <span key={r} className="text-[9px] px-1.5 py-0.5 rounded bg-[#2E2E38] text-[#38BDF8] font-semibold">{r}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-gray-400 text-xs">
                    Intelligence Report &bull; {form.analyst || "Analyst"}
                  </div>
                )}
              </div>
              <div className="text-right text-[10px] text-gray-500">
                <div>Period: Last {form.days || 30} days</div>
                <div>{form.generated_at ? new Date(form.generated_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : ""}</div>
              </div>
            </div>
          </div>

          {/* ── Executive Summary ── */}
          <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
            <SectionTitle>Executive Summary</SectionTitle>
            <EditableText
              value={form.executive_summary}
              onChange={(v) => update("executive_summary", v)}
              placeholder="Write an executive summary for this report..."
              multiline
            />
          </div>

          {/* ── KPI Overview ── */}
          {form.overview && (
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
              <SectionTitle>Overview</SectionTitle>
              <div className="flex gap-3 flex-wrap">
                <KpiCard label="Total CVEs" value={form.overview.total_cves} onChange={(v) => updateOverview("total_cves", v)} />
                <KpiCard label="Threats" value={form.overview.total_threats} onChange={(v) => updateOverview("total_threats", v)} />
                <KpiCard label="News" value={form.overview.total_news} onChange={(v) => updateOverview("total_news", v)} />
                <KpiCard label="Open Alerts" value={form.overview.open_alerts} onChange={(v) => updateOverview("open_alerts", v)} />
                <KpiCard label="CVEs (24h)" value={form.overview.new_cves_24h} onChange={(v) => updateOverview("new_cves_24h", v)} />
              </div>
            </div>
          )}

          {/* ── Severity Breakdown ── */}
          {form.severity && (
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
              <SectionTitle>Severity Breakdown</SectionTitle>
              <SeverityBar data={form.severity} />
              <EditableText
                value={form.severity_commentary}
                onChange={(v) => update("severity_commentary", v)}
                placeholder="Add commentary on severity distribution..."
                multiline
                className="mt-3"
              />
            </div>
          )}

          {/* ── Top Products ── */}
          {form.products && form.products.length > 0 && (
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
              <SectionTitle>Top Affected Products</SectionTitle>
              <ProductsBar data={form.products} />
              <EditableText
                value={form.products_commentary}
                onChange={(v) => update("products_commentary", v)}
                placeholder="Add commentary on affected products..."
                multiline
                className="mt-3"
              />
            </div>
          )}

          {/* ── Sector Exposure ── */}
          {form.sectors && form.sectors.length > 0 && (
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
              <SectionTitle>Sector Exposure</SectionTitle>
              <SectorsPie data={form.sectors} />
              <EditableText
                value={form.sectors_commentary}
                onChange={(v) => update("sectors_commentary", v)}
                placeholder="Add commentary on sector exposure..."
                multiline
                className="mt-3"
              />
            </div>
          )}

          {/* ── Regional Landscape ── */}
          {form.regions && form.regions.length > 0 && (
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
              <SectionTitle>Regional Threat Landscape</SectionTitle>
              <RegionsBar data={form.regions} />
              <div className="flex items-center gap-4 mt-2 text-[9px] text-gray-500">
                <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-[#f97316] rounded-sm" /> Threats</span>
                <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-[#0ea5e9] rounded-sm" /> News</span>
              </div>
              <DataTable
                columns={[
                  { key: "region", label: "Region" },
                  { key: "threat_count", label: "Threats", editable: true },
                  { key: "news_count", label: "News", editable: true },
                  { key: "avg_risk_score", label: "Avg Risk" },
                ]}
                rows={form.regions}
                editable
                onCellEdit={(ri, key, val) => {
                  const regions = [...form.regions];
                  regions[ri] = { ...regions[ri], [key]: val };
                  update("regions", regions);
                }}
              />
              <EditableText
                value={form.regions_commentary}
                onChange={(v) => update("regions_commentary", v)}
                placeholder="Add commentary on regional landscape..."
                multiline
                className="mt-3"
              />
            </div>
          )}

          {/* ── Client CVE Exposure (client reports) ── */}
          {isClient && clientData && (
            <>
              {clientData.products_by_cve && clientData.products_by_cve.length > 0 && (
                <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
                  <SectionTitle>CVE Exposure by Product</SectionTitle>
                  <ProductsBar data={clientData.products_by_cve} />
                </div>
              )}

              {clientData.regional_exposure && clientData.regional_exposure.length > 0 && (
                <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
                  <SectionTitle>Regional Exposure</SectionTitle>
                  <RegionsBar data={clientData.regional_exposure} />
                </div>
              )}

              <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
                <SectionTitle>Client CVE Table</SectionTitle>
                <DataTable
                  columns={[
                    { key: "cve_id", label: "CVE ID" },
                    { key: "title", label: "Title", editable: true, render: (v) => <span className="truncate max-w-[200px] block">{v || "—"}</span> },
                    { key: "cvss", label: "CVSS", render: (v) => <span className="font-bold">{v}</span> },
                    { key: "severity", label: "Severity", render: (v) => <SevBadge severity={v} /> },
                    { key: "product", label: "Product" },
                    { key: "source", label: "Source" },
                  ]}
                  rows={clientData.cve_exposure}
                  editable
                  onCellEdit={updateCveCell}
                />
              </div>
            </>
          )}

          {/* ── Client Exposure (general reports) ── */}
          {!isClient && form.exposure && form.exposure.length > 0 && (
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
              <SectionTitle>Client Exposure Analysis</SectionTitle>
              <DataTable
                columns={[
                  { key: "client_name", label: "Client", editable: true },
                  { key: "company", label: "Company" },
                  { key: "matching_cve_count", label: "Matching CVEs", editable: true, render: (v) => <span className="font-bold">{v}</span> },
                  { key: "regions", label: "Regions", render: (v) => (
                    <div className="flex flex-wrap gap-0.5">
                      {(v || []).map((r) => <span key={r} className="text-[8px] px-1 py-0.5 bg-[#2a2a4a] rounded text-gray-300">{r}</span>)}
                      {(!v || v.length === 0) && "—"}
                    </div>
                  )},
                ]}
                rows={form.exposure}
                editable
                onCellEdit={updateExposureCell}
              />
            </div>
          )}

          {/* ── Advisory History ── */}
          {form.advisories && form.advisories.length > 0 && (
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
              <SectionTitle>Advisory History</SectionTitle>
              <DataTable
                columns={[
                  { key: "kind", label: "Type", render: (v) => (
                    <span className={`text-[9px] font-semibold px-1.5 py-0.5 rounded border ${
                      v === "CVE" ? "text-blue-300 border-blue-800 bg-blue-900/20"
                      : v === "News" ? "text-cyan-300 border-cyan-800 bg-cyan-900/20"
                      : "text-orange-300 border-orange-800 bg-orange-900/20"
                    }`}>{v}</span>
                  )},
                  { key: "identifier", label: "ID" },
                  { key: "title", label: "Title", render: (v) => <span className="truncate max-w-[250px] block">{v || "—"}</span> },
                  { key: "sent_at", label: "Sent", render: (v) => v ? v.slice(0, 10) : "—" },
                  { key: "sent_by", label: "By" },
                ]}
                rows={form.advisories}
              />
            </div>
          )}

          {/* ── Critical CVEs (general only) ── */}
          {!isClient && form.cves && form.cves.length > 0 && (
            <div className="bg-[#12121e] border border-[#2a2a4a] rounded-xl p-5">
              <SectionTitle>Critical CVEs (CVSS 9.0+)</SectionTitle>
              <DataTable
                columns={[
                  { key: "cve_id", label: "CVE ID" },
                  { key: "title", label: "Title", editable: true, render: (v) => <span className="truncate max-w-[250px] block">{v || "—"}</span> },
                  { key: "score", label: "CVSS", render: (v) => <span className="font-bold">{v}</span> },
                  { key: "severity", label: "Severity", render: (v) => <SevBadge severity={v} /> },
                  { key: "vendor", label: "Vendor" },
                ]}
                rows={form.cves}
                editable
                onCellEdit={updateCveCell}
              />
            </div>
          )}

          {/* ── Footer ── */}
          <div className="bg-[#2E2E38] rounded-xl p-4 text-center">
            <p className="text-[10px] text-gray-500 italic">
              &copy; Cyber Threat Watch
            </p>
            <p className="text-[9px] text-gray-600 mt-0.5 italic">
              This report is intended for the named recipients and contains confidential information.
            </p>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}
