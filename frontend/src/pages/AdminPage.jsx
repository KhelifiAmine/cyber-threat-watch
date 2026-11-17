import { useState, useEffect, useCallback } from "react";
import api from "../api/axios";
import { errorMessage } from "../api/errors";
import ConfirmModal from "../components/ui/ConfirmModal";

const NOTIFICATION_ROLE_LABELS = {
  analyst:       "All alerts",
  client:        "Urgent only",
  not_concerned: "No emails",
};

const NOTIFICATION_ROLE_STYLE = {
  analyst:       "text-blue-400",
  client:        "text-green-400",
  not_concerned: "text-gray-500",
};

export default function AdminPage() {
  const [users, setUsers]             = useState([]);
  const [recipients, setRecipients]   = useState([]);
  const [loading, setLoading]         = useState(true);
  const [showCreate, setShowCreate]   = useState(false);
  const [form, setForm]               = useState({ email: "", full_name: "", password: "", role: "analyst" });
  const [error, setError]             = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState(null); // { id, email }

  const fetchAll = useCallback(async () => {
    try {
      const [uRes, rRes] = await Promise.all([
        api.get("/api/admin/users"),
        api.get("/api/notifications/recipients"),
      ]);
      setUsers(uRes.data || []);
      setRecipients(rRes.data.recipients || []);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Merge users with their recipient record by email
  const merged = users.map(u => {
    const rec = recipients.find(r => r.email === u.email);
    return { ...u, notification_role: rec?.role ?? null, recipient_id: rec?.id ?? null };
  });

  const handleCreate = async (e) => {
    e.preventDefault();
    setError("");
    try {
      await api.post("/api/auth/register", form);
      setShowCreate(false);
      setForm({ email: "", full_name: "", password: "", role: "analyst" });
      fetchAll();
    } catch (err) {
      setError(errorMessage(err, "Failed to create user"));
    }
  };

  const handleRoleChange = async (userId, newRole) => {
    try {
      await api.patch(`/api/admin/users/${userId}`, { role: newRole });
      fetchAll();
    } catch { /* ignore */ }
  };

  const handleToggleActive = async (userId, current) => {
    try {
      await api.patch(`/api/admin/users/${userId}`, { is_active: !current });
      fetchAll();
    } catch { /* ignore */ }
  };

  const handleDelete = async (userId) => {
    try {
      await api.delete(`/api/admin/users/${userId}`);
      fetchAll();
    } catch { /* ignore */ }
    setDeleteConfirm(null);
  };

  const handleNotifRoleChange = async (recipientId, newRole) => {
    if (!recipientId) return;
    try {
      await api.put(`/api/notifications/recipients/${recipientId}`, { role: newRole });
      fetchAll();
    } catch { /* ignore */ }
  };

  return (
    <div className="space-y-6">
      {deleteConfirm && (
        <ConfirmModal
          message={`Delete user ${deleteConfirm.email}? This cannot be undone.`}
          confirmLabel="Delete"
          danger
          onConfirm={() => handleDelete(deleteConfirm.id)}
          onCancel={() => setDeleteConfirm(null)}
        />
      )}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Administration</h1>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-4 py-1.5 text-xs rounded bg-[#38BDF8]/10 border border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20"
        >
          {showCreate ? "Cancel" : "+ New User"}
        </button>
      </div>

      {showCreate && (
        <form onSubmit={handleCreate} className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-4 space-y-3">
          {error && <div className="text-red-400 text-sm">{error}</div>}
          <div className="grid grid-cols-2 gap-3">
            <input type="email" placeholder="Email" required value={form.email}
              onChange={e => setForm({ ...form, email: e.target.value })}
              className="px-3 py-2 bg-[#0f0f23] border border-[#2a2a4a] rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#38BDF8]/50" />
            <input type="text" placeholder="Full Name" required value={form.full_name}
              onChange={e => setForm({ ...form, full_name: e.target.value })}
              className="px-3 py-2 bg-[#0f0f23] border border-[#2a2a4a] rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#38BDF8]/50" />
            <input type="password" placeholder="Password (min 8 chars)" required minLength={8} value={form.password}
              onChange={e => setForm({ ...form, password: e.target.value })}
              className="px-3 py-2 bg-[#0f0f23] border border-[#2a2a4a] rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#38BDF8]/50" />
            <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}
              className="px-3 py-2 bg-[#0f0f23] border border-[#2a2a4a] rounded text-sm text-gray-300 focus:outline-none focus:border-[#38BDF8]/50">
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
              <option value="client">Client</option>
            </select>
          </div>
          <button type="submit" className="px-4 py-2 text-xs rounded bg-[#38BDF8] text-[#1a1a2e] font-semibold hover:bg-[#0EA5E9]">
            Create User
          </button>
        </form>
      )}

      <div className="bg-[#12121e] border border-[#2a2a4a] rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2a4a] text-gray-500 text-xs uppercase">
              <th className="text-left px-4 py-3 font-medium">Email</th>
              <th className="text-left px-4 py-3 font-medium">Name</th>
              <th className="text-left px-4 py-3 font-medium w-28">Role</th>
              <th className="text-left px-4 py-3 font-medium w-44">Email Alerts</th>
              <th className="text-left px-4 py-3 font-medium w-20">Active</th>
              <th className="text-left px-4 py-3 font-medium w-28">Last Login</th>
              <th className="px-4 py-3 w-16"></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-600">Loading...</td></tr>
            ) : merged.map(u => (
              <tr key={u.id} className="border-b border-[#1e1e3a]">
                <td className="px-4 py-3 text-gray-200">{u.email}</td>
                <td className="px-4 py-3 text-gray-300">{u.full_name}</td>
                <td className="px-4 py-3">
                  <select value={u.role} onChange={e => handleRoleChange(u.id, e.target.value)}
                    className="px-2 py-1 bg-[#0f0f23] border border-[#2a2a4a] rounded text-xs text-gray-300">
                    <option value="admin">Admin</option>
                    <option value="analyst">Analyst</option>
                    <option value="client">Client</option>
                  </select>
                </td>
                <td className="px-4 py-3">
                  {u.recipient_id ? (
                    <select
                      value={u.notification_role}
                      onChange={e => handleNotifRoleChange(u.recipient_id, e.target.value)}
                      className={`px-2 py-1 bg-[#0f0f23] border border-[#2a2a4a] rounded text-xs font-medium ${NOTIFICATION_ROLE_STYLE[u.notification_role] || "text-gray-400"}`}
                    >
                      <option value="analyst">All alerts</option>
                      <option value="client">Urgent only</option>
                      <option value="not_concerned">No emails</option>
                    </select>
                  ) : (
                    <span className="text-xs text-gray-600">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <button onClick={() => handleToggleActive(u.id, u.is_active)}
                    className={`text-xs px-2 py-0.5 rounded border ${u.is_active ? "border-green-700 text-green-400 bg-green-900/20" : "border-red-700 text-red-400 bg-red-900/20"}`}>
                    {u.is_active ? "Active" : "Inactive"}
                  </button>
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs">
                  {u.last_login ? new Date(u.last_login).toLocaleString() : "Never"}
                </td>
                <td className="px-4 py-3">
                  <button onClick={() => setDeleteConfirm({ id: u.id, email: u.email })}
                    className="text-xs px-2 py-0.5 rounded border border-red-800 text-red-400 hover:bg-red-900/30">
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
