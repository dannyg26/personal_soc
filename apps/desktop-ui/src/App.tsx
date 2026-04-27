import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import DashboardPage from "./pages/DashboardPage";
import ProcessesPage from "./pages/ProcessesPage";
import AlertsPage from "./pages/AlertsPage";
import StartupPage from "./pages/StartupPage";
import ProcessDetailPage from "./pages/ProcessDetailPage";
import EventsPage from "./pages/EventsPage";
import SettingsPage from "./pages/SettingsPage";
import PhishingDetectorPage from "./pages/PhishingDetectorPage";
import MaliciousLinkDetectorPage from "./pages/MaliciousLinkDetectorPage";
import PasswordManagerPage from "./pages/PasswordManagerPage";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="processes" element={<ProcessesPage />} />
        <Route path="processes/:processId" element={<ProcessDetailPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="startup" element={<StartupPage />} />
        <Route path="events" element={<EventsPage />} />
        <Route path="assistant" element={<Navigate to="/dashboard" replace />} />
        <Route path="phishing-detector" element={<PhishingDetectorPage />} />
        <Route path="malicious-link-detector" element={<MaliciousLinkDetectorPage />} />
        <Route path="password-manager" element={<PasswordManagerPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}
