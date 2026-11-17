import { useNavigate } from "react-router-dom";
import HoverDetail from "../ui/HoverDetail";

export default function ClientExposureTable({ data }) {
  const navigate = useNavigate();

  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[200px] text-gray-600 text-sm">
        No client exposure data
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-xs uppercase tracking-wider border-b border-[#2a2a4a]">
            <th className="text-left py-2 pr-2">Client</th>
            <th className="text-left py-2 pr-2">Company</th>
            <th className="text-center py-2 pr-2">CVEs</th>
            <th className="text-left py-2">Top Product</th>
          </tr>
        </thead>
        <tbody>
          {data.map((client, i) => (
            <HoverDetail
              key={i}
              content={() => (
                <div className="text-xs">
                  <p className="text-white font-medium mb-1">{client.client_name}</p>
                  {client.sector && <p className="text-gray-400 mb-1">Sector: {client.sector}</p>}
                  <p className="text-gray-500 mb-1">All matched products:</p>
                  <ul className="list-disc list-inside text-gray-400">
                    {client.top_products?.map((p, j) => (
                      <li key={j}>{p.name} ({p.cve_count} CVEs)</li>
                    ))}
                  </ul>
                </div>
              )}
            >
              <tr
                className="border-b border-[#2a2a4a]/50 hover:bg-[#161628] cursor-pointer transition-colors"
                onClick={() => navigate("/clients")}
              >
                <td className="py-2 pr-2 text-gray-300">{client.client_name}</td>
                <td className="py-2 pr-2 text-gray-500">{client.company}</td>
                <td className="py-2 pr-2 text-center">
                  <span className="text-[#38BDF8] font-bold">{client.matching_cve_count}</span>
                </td>
                <td className="py-2 text-gray-400 truncate max-w-[120px]">
                  {client.top_products?.[0]?.name || "—"}
                </td>
              </tr>
            </HoverDetail>
          ))}
        </tbody>
      </table>
    </div>
  );
}
