import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import { ToastProvider } from "./context/ToastContext";
import ProtectedRoute from "./components/ProtectedRoute";
import AppLayout from "./components/layout/AppLayout";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import ThreatsPage from "./pages/ThreatsPage";
import CVEsPage from "./pages/CVEsPage";
import AdminPage from "./pages/AdminPage";
import LogsPage from "./pages/LogsPage";
import ScraperPage from "./pages/ScraperPage";
import ReviewPage from "./pages/ReviewPage";
import ClientsPage from "./pages/ClientsPage";
import NewsPage from "./pages/NewsPage";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
      <ToastProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          {/* All protected pages share the sidebar + topbar layout */}
          <Route
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/threats" element={<ThreatsPage />} />
            <Route path="/cves" element={<CVEsPage />} />
            <Route path="/news" element={<NewsPage />} />
<Route
              path="/admin"
              element={
                <ProtectedRoute roles={["admin"]}>
                  <AdminPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/logs"
              element={
                <ProtectedRoute roles={["admin"]}>
                  <LogsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/review"
              element={
                <ProtectedRoute roles={["admin", "analyst"]}>
                  <ReviewPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/scraper"
              element={
                <ProtectedRoute roles={["admin", "analyst"]}>
                  <ScraperPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/clients"
              element={
                <ProtectedRoute roles={["admin", "analyst"]}>
                  <ClientsPage />
                </ProtectedRoute>
              }
            />
          </Route>

          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
