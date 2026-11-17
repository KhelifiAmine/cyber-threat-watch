import { NavLink } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

const roleBadgeColors = {
  admin: "bg-red-900/40 text-red-400 border-red-700",
  analyst: "bg-blue-900/40 text-blue-400 border-blue-700",
  client: "bg-green-900/40 text-green-400 border-green-700",
};

function getNavSections(role) {
  const isClient = role === "client";

  if (isClient) {
    return [
      {
        label: "Overview",
        items: [
          { to: "/dashboard", label: "My Dashboard", icon: "grid" },
        ],
      },
      {
        label: "Intelligence",
        items: [
          { to: "/threats", label: "Threat Intel", icon: "shield" },
          { to: "/cves", label: "Vulnerabilities", icon: "bug" },
          { to: "/news", label: "Security News", icon: "news" },
        ],
      },
    ];
  }

  return [
    {
      label: "Overview",
      items: [
        { to: "/dashboard", label: "Dashboard", icon: "grid" },
      ],
    },
    {
      label: "Intelligence",
      items: [
        { to: "/threats", label: "Threats", icon: "shield" },
        { to: "/cves", label: "CVEs", icon: "bug" },
        { to: "/news", label: "News", icon: "news" },
      ],
    },
    {
      label: "Operations",
      items: [
        { to: "/review", label: "Review Queue", icon: "review", roles: ["admin", "analyst"] },
        { to: "/scraper", label: "Scrapers", icon: "scraper", roles: ["admin", "analyst"] },
        { to: "/clients", label: "Clients", icon: "clients", roles: ["admin", "analyst"] },
      ],
    },
    {
      label: "Administration",
      items: [
        { to: "/admin", label: "Admin", icon: "settings", roles: ["admin"] },
        { to: "/logs", label: "Audit Log", icon: "log", roles: ["admin"] },
      ],
    },
  ];
}

const icons = {
  grid: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
    </svg>
  ),
  shield: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  bug: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 9v2m0 4h.01M5.07 19H19a2 2 0 001.75-2.96l-6.93-12a2 2 0 00-3.5 0l-6.93 12A2 2 0 005.07 19z" />
    </svg>
  ),
  settings: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
  log: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
    </svg>
  ),
  scraper: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
  ),
  review: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
    </svg>
  ),
  news: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z" />
    </svg>
  ),
  clients: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
};

export default function Sidebar({ collapsed, onToggle }) {
  const { user, logout } = useAuth();
  const role = user?.role || "analyst";
  const sections = getNavSections(role);

  return (
    <aside
      className={`fixed top-0 left-0 h-full bg-[#12121e] border-r border-[#2a2a4a] flex flex-col transition-all duration-200 z-30 ${
        collapsed ? "w-16" : "w-56"
      }`}
    >
      {/* Brand */}
      <div className="flex items-center h-14 px-4 border-b border-[#2a2a4a]">
        {!collapsed && (
          <span className="text-[#38BDF8] font-bold text-sm tracking-wide whitespace-nowrap">
            Cyber Threat Watch
          </span>
        )}
        <button
          onClick={onToggle}
          className={`text-gray-500 hover:text-gray-300 transition-colors ${
            collapsed ? "mx-auto" : "ml-auto"
          }`}
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
      </div>

      {/* Nav Sections */}
      <nav className="flex-1 py-3 px-2 overflow-y-auto">
        {sections.map((section) => {
          const visibleItems = section.items.filter(
            (item) => !item.roles || item.roles.includes(role)
          );
          if (visibleItems.length === 0) return null;

          return (
            <div key={section.label} className="mb-3">
              {!collapsed && (
                <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-600 px-3 mb-1.5">
                  {section.label}
                </p>
              )}
              {collapsed && <div className="h-px bg-[#2a2a4a] mx-2 mb-2" />}
              <div className="space-y-0.5">
                {visibleItems.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                        isActive
                          ? "bg-[#38BDF8]/10 text-[#38BDF8]"
                          : "text-gray-400 hover:bg-[#1a1a2e] hover:text-gray-200"
                      } ${collapsed ? "justify-center" : ""}`
                    }
                  >
                    {icons[item.icon]}
                    {!collapsed && <span>{item.label}</span>}
                  </NavLink>
                ))}
              </div>
            </div>
          );
        })}
      </nav>

      {/* User profile + Sign out */}
      <div className="border-t border-[#2a2a4a] px-3 py-3 shrink-0">
        {!collapsed ? (
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-full bg-[#1a1a2e] border border-[#2a2a4a] flex items-center justify-center text-xs font-bold text-gray-300 shrink-0">
              {(user?.full_name || "U").charAt(0).toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-gray-200 truncate leading-tight">{user?.full_name || "User"}</p>
              <span
                className={`text-[10px] px-1.5 py-0.5 rounded border uppercase font-medium ${
                  roleBadgeColors[role] || roleBadgeColors.analyst
                }`}
              >
                {role}
              </span>
            </div>
            <button
              onClick={logout}
              className="text-gray-500 hover:text-red-400 hover:bg-red-900/20 transition-colors shrink-0 p-2 rounded"
              title="Sign out"
            >
              <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        ) : (
          <button
            onClick={logout}
            className="w-full flex justify-center text-gray-600 hover:text-red-400 transition-colors"
            title="Sign out"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.8}
                d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
              />
            </svg>
          </button>
        )}
      </div>
    </aside>
  );
}
