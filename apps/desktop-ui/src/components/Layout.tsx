import { Outlet, NavLink } from "react-router-dom";
import { useEffect, useCallback } from "react";
import {
  LayoutDashboard,
  Cpu,
  Bell,
  Rocket,
  Settings,
  PauseCircle,
  PlayCircle,
  Activity,
  FishOff,
  Link2Off,
  KeyRound,
} from "lucide-react";
import { useAppStore } from "@/store";
import {
  getSystemOverview,
  listProcessesPaged,
  listAlerts,
  listStartupEntries,
  pauseMonitoring,
  resumeMonitoring,
} from "@/lib/invoke";
import { AssistantSignalProvider } from "@/components/AssistantSignalContext";
import GlobalAssistant from "@/components/GlobalAssistant";

import robotLogo from "@/assets/robot.png";

const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/processes", label: "Processes", icon: Cpu },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/startup", label: "Startup", icon: Rocket },
  { to: "/events", label: "Events", icon: Activity },
  { to: "/phishing-detector", label: "Phishing Detector", icon: FishOff },
  { to: "/malicious-link-detector", label: "Malicious Link Detector", icon: Link2Off },
  { to: "/password-manager", label: "Password Manager", icon: KeyRound },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function Layout() {
  const {
    overview,
    isMonitoringPaused,
    setOverview,
    setProcesses,
    setAlerts,
    setStartupEntries,
    setMonitoringPaused,
  } = useAppStore();

  // Core data: overview + alerts + startup — refresh every 15s
  const refreshCore = useCallback(async () => {
    try {
      const [ov, alerts, startup] = await Promise.all([
        getSystemOverview(),
        listAlerts(200),
        listStartupEntries(),
      ]);
      setOverview(ov);
      setAlerts(alerts);
      setStartupEntries(startup);
    } catch (err) {
      console.error("Failed to refresh core data:", err);
    }
  }, [setOverview, setAlerts, setStartupEntries]);

  // Processes: top 200 by risk score for app-wide views and helpers — refresh every 30s
  const refreshProcesses = useCallback(async () => {
    try {
      const result = await listProcessesPaged("", "", "risk_score", false, 200, 0);
      setProcesses(result.processes);
    } catch (err) {
      console.error("Failed to refresh processes:", err);
    }
  }, [setProcesses]);

  useEffect(() => {
    refreshCore();
    const interval = setInterval(refreshCore, 15000);
    return () => clearInterval(interval);
  }, [refreshCore]);

  useEffect(() => {
    refreshProcesses();
    const interval = setInterval(refreshProcesses, 30000);
    return () => clearInterval(interval);
  }, [refreshProcesses]);

  const handleToggleMonitoring = async () => {
    try {
      if (isMonitoringPaused) {
        await resumeMonitoring();
        setMonitoringPaused(false);
      } else {
        await pauseMonitoring();
        setMonitoringPaused(true);
      }
    } catch (err) {
      console.error("Failed to toggle monitoring:", err);
    }
  };

  const healthColor =
    !overview
      ? "var(--text-muted)"
      : overview.health_score >= 80
      ? "var(--color-green)"
      : overview.health_score >= 50
      ? "var(--color-yellow)"
      : "var(--color-red)";

  return (
    <AssistantSignalProvider>
      <div style={styles.shell}>
      {/* Sidebar */}
      <aside style={styles.sidebar}>
        <div style={styles.logoArea}>
  <img
    src={robotLogo}
    style={{
      width: 30,
      height: 30,
      objectFit: "contain",
      borderRadius: 6,
    }}
  />

  <span style={styles.logoText}>Threat-Guard</span>
</div>

        {/* Health indicator */}
        <div style={styles.healthBar}>
          <span style={styles.healthLabel}>System Health</span>
          <span style={{ ...styles.healthScore, color: healthColor }}>
            {overview ? `${overview.health_score}%` : "—"}
          </span>
        </div>

        <nav style={styles.nav}>
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              style={({ isActive }) => ({
                ...styles.navLink,
                ...(isActive ? styles.navLinkActive : {}),
              })}
            >
              <Icon size={16} />
              <span>{label}</span>
              {to === "/alerts" && overview && overview.active_alerts_count > 0 && (
                <span style={styles.alertBadge}>{overview.active_alerts_count}</span>
              )}
            </NavLink>
          ))}
        </nav>

        <div style={styles.sidebarFooter}>
          <button
            className="btn btn-ghost"
            style={{ width: "100%", justifyContent: "center" }}
            onClick={handleToggleMonitoring}
          >
            {isMonitoringPaused ? (
              <>
                <PlayCircle size={15} />
                Resume Monitoring
              </>
            ) : (
              <>
                <PauseCircle size={15} />
                Pause Monitoring
              </>
            )}
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main style={styles.main}>
        <Outlet />
      </main>

      <GlobalAssistant />
      </div>
    </AssistantSignalProvider>
  );
}

const styles: Record<string, React.CSSProperties> = {
  shell: {
    display: "flex",
    height: "100vh",
    overflow: "hidden",
    background: "var(--bg-primary)",
  },
  sidebar: {
    width: 224,
    flexShrink: 0,
    background: "var(--bg-secondary)",
    borderRight: "1px solid var(--border)",
    display: "flex",
    flexDirection: "column",
    padding: "0",
  },
  logoArea: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    padding: "18px 18px 16px",
    borderBottom: "1px solid var(--border)",
    marginBottom: 10,
  },
  logoText: {
    fontWeight: 700,
    fontSize: 15,
    color: "var(--text-primary)",
    letterSpacing: "-0.02em",
  },
  logoSub: {
    fontSize: 10,
    color: "var(--text-muted)",
    letterSpacing: "0.04em",
    textTransform: "uppercase" as const,
    marginLeft: "auto",
  },
  healthBar: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "6px 16px 10px",
    marginBottom: 2,
  },
  healthLabel: {
    fontSize: 10,
    color: "var(--text-muted)",
    textTransform: "uppercase" as const,
    letterSpacing: "0.06em",
    fontWeight: 600,
  },
  healthScore: {
    fontSize: 13,
    fontWeight: 700,
  },
  nav: {
    display: "flex",
    flexDirection: "column",
    gap: 1,
    padding: "0 10px",
    flex: 1,
  },
  navLink: {
    display: "flex",
    alignItems: "center",
    gap: 9,
    padding: "9px 10px",
    borderRadius: "var(--radius-md)",
    color: "var(--text-secondary)",
    textDecoration: "none",
    fontSize: 13,
    fontWeight: 500,
    transition: "all 0.12s ease",
  },
  navLinkActive: {
    background: "rgba(96,165,250,0.1)",
    color: "var(--color-blue)",
  },
  alertBadge: {
    marginLeft: "auto",
    background: "rgba(248,113,113,0.2)",
    color: "var(--color-red)",
    border: "1px solid rgba(248,113,113,0.3)",
    borderRadius: "999px",
    fontSize: 10,
    fontWeight: 700,
    padding: "1px 7px",
    minWidth: 18,
    textAlign: "center",
  },
  sidebarFooter: {
    padding: "10px 10px 12px",
    borderTop: "1px solid var(--border)",
    marginTop: 4,
  },
  main: {
    flex: 1,
    overflow: "auto",
    padding: "24px 28px",
  },
};
