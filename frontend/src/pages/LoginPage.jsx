import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { errorMessage } from "../api/errors";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);

    try {
      await login(email, password);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(errorMessage(err, "Login failed. Check your credentials."));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a1a] flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-[#38BDF8] tracking-wide">
            Cyber Threat Watch
          </h1>
          <p className="text-gray-500 mt-2 text-sm">
            Threat Intelligence Platform
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-[#1a1a2e] border border-[#2a2a4a] rounded-lg p-8">
          <h2 className="text-xl font-semibold text-white mb-6">Sign In</h2>

          {error && (
            <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded text-red-400 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-gray-400 text-sm mb-1.5">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
                className="w-full px-4 py-2.5 bg-[#0f0f23] border border-[#2a2a4a] rounded text-white placeholder-gray-600 focus:outline-none focus:border-[#38BDF8] transition-colors"
                placeholder="analyst@example.com"
              />
            </div>

            <div>
              <label className="block text-gray-400 text-sm mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full px-4 py-2.5 bg-[#0f0f23] border border-[#2a2a4a] rounded text-white placeholder-gray-600 focus:outline-none focus:border-[#38BDF8] transition-colors"
                placeholder="Enter your password"
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 bg-[#38BDF8] text-[#1a1a2e] font-semibold rounded hover:bg-[#0EA5E9] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? "Signing in..." : "Sign In"}
            </button>
          </form>

          <p className="text-gray-600 text-xs mt-6 text-center">
            Access is restricted. Contact your administrator for an account.
          </p>
        </div>

        {/* Footer */}
        <p className="text-gray-700 text-xs mt-6 text-center">
          &copy; {new Date().getFullYear()} Cyber Threat Watch
        </p>
      </div>
    </div>
  );
}
