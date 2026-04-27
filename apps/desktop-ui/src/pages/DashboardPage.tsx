import { useAppStore } from "@/store";
import {
  ShieldCheck,
  AlertTriangle,
  Cpu,
  Rocket,
  Eye,
  TrendingUp,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  RadialBarChart,
  RadialBar,
  BarChart,
  Bar,
} from "recharts";
import { formatDistanceToNow } from "date-fns";
import { useNavigate } from "react-router-dom";

// Custom tooltip style
const tooltipStyle = {
  background: "#2A2520",
  border: "1px solid #48423B",
  borderRadius: 8,
  fontSize: 12,
  color: "#F7F0E6",
  boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
};

export default function DashboardPage() {
  const { overview, alerts, processes } = useAppStore();
  const navigate = useNavigate();
  const gaugeSize = 164;
  const gaugeCenter = gaugeSize / 2;

  const recentAlerts = [...alerts]
    .filter((a) => a.status === "open")
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 6);

  const topRiskProcesses = processes
    .filter((p) => p.risk_score > 0)
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 5);

  // Health gauge data
  const healthScore = overview?.health_score ?? 0;
  const healthColor =
    healthScore >= 80 ? "#4ADE80" : healthScore >= 50 ? "#FBBF24" : "#F87171";

  const healthGaugeData = [
    { value: healthScore, fill: healthColor },
    { value: 100 - healthScore, fill: "rgba(255,255,255,0.04)" },
  ];

  // Process status donut
  const running = processes.filter((p) => p.current_status === "Running").length;
  const suspicious = processes.filter((p) => p.risk_score >= 25).length;
  const trusted = processes.filter((p) => p.current_status === "Trusted").length;
  const terminated = processes.filter((p) => p.current_status === "Terminated").length;

  const statusData = [
    { name: "Running", value: running, color: "#4ADE80" },
    { name: "At Risk", value: suspicious, color: "#FB923C" },
    { name: "Trusted", value: trusted, color: "#60A5FA" },
    { name: "Terminated", value: terminated, color: "#6B5E52" },
  ].filter((d) => d.value > 0);

  // Alert severity bar chart
  const severityCounts = {
    high: alerts.filter((a) => a.severity === "high").length,
    medium: alerts.filter((a) => a.severity === "medium").length,
    low: alerts.filter((a) => a.severity === "low").length,
    info: alerts.filter((a) => a.severity === "info").length,
  };
  const alertBarData = [
    { name: "High", count: severityCounts.high, color: "#F87171" },
    { name: "Medium", count: severityCounts.medium, color: "#FBBF24" },
    { name: "Low", count: severityCounts.low, color: "#4ADE80" },
    { name: "Info", count: severityCounts.info, color: "#60A5FA" },
  ];

  // Risk distribution sparkline (top 15 processes by risk)
  const riskSparkData = processes
    .filter((p) => p.risk_score > 0)
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 15)
    .map((p) => ({ name: p.name.replace(".exe", ""), risk: p.risk_score }));

  const statCards = overview
    ? [
        {
          label: "Health Score",
          value: `${overview.health_score}%`,
          icon: ShieldCheck,
          color: healthColor,
          glow: healthColor,
        },
        {
          label: "Active Alerts",
          value: overview.active_alerts_count,
          icon: AlertTriangle,
          color: "#F87171",
          glow: "#F87171",
        },
        {
          label: "At Risk",
          value: overview.suspicious_processes_count,
          icon: Eye,
          color: "#FB923C",
          glow: "#FB923C",
        },
        {
          label: "Monitored",
          value: overview.monitored_processes_count,
          icon: Cpu,
          color: "#60A5FA",
          glow: "#60A5FA",
        },
        {
          label: "Startup Entries",
          value: overview.startup_changes_count,
          icon: Rocket,
          color: "#A78BFA",
          glow: "#A78BFA",
        },
      ]
    : [];

  return (
    <div style={{ width: "100%", maxWidth: 1420 }}>
      {/* Header */}
      <div style={s.header}>
        <div>
          <h1 style={s.pageTitle}>Dashboard</h1>
          {overview && (
            <p style={s.pageSubtitle}>
              Updated {formatDistanceToNow(new Date(overview.timestamp), { addSuffix: true })}
            </p>
          )}
        </div>
        <div style={s.headerBadge}>
          <div style={{ ...s.dot, background: "#4ADE80" }} />
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            Live monitoring
          </span>
        </div>
      </div>

      {/* Stat cards */}
      <div style={s.statsGrid}>
        {statCards.map(({ label, value, icon: Icon, color, glow }) => (
          <div key={label} className="card" style={{ ...s.statCard, "--glow": glow } as React.CSSProperties}>
            <div style={{ ...s.statIconWrap, background: `${color}18`, border: `1px solid ${color}28` }}>
              <Icon size={18} color={color} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ ...s.statValue, color }}>{value}</div>
              <div style={s.statLabel}>{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Row 2: Health gauge + Process donut + Alert severity bars */}
      <div style={s.threeCol}>
        {/* Health gauge */}
        <div className="card" style={s.gaugeCard}>
          <div style={s.cardHeader}>
            <ShieldCheck size={14} color="var(--text-muted)" />
            <span style={s.cardTitle}>System Health</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1 }}>
            <div style={{ position: "relative", width: gaugeSize, height: gaugeSize }}>
              <RadialBarChart
                width={gaugeSize}
                height={gaugeSize}
                cx={gaugeCenter}
                cy={gaugeCenter}
                innerRadius={58}
                outerRadius={76}
                startAngle={90}
                endAngle={-270}
                data={healthGaugeData}
                barSize={14}
              >
                <RadialBar dataKey="value" cornerRadius={6} background={{ fill: "rgba(255,255,255,0.04)" }}>
                  {healthGaugeData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </RadialBar>
              </RadialBarChart>
              <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                <span style={{ fontSize: 31, fontWeight: 700, color: healthColor, lineHeight: 1 }}>{healthScore}</span>
                <span style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>/ 100</span>
              </div>
            </div>
            <div style={{ marginTop: 12, textAlign: "center" }}>
              <span style={{ fontSize: 14, fontWeight: 600, color: healthColor }}>
                {healthScore >= 80 ? "Healthy" : healthScore >= 50 ? "Moderate" : "At Risk"}
              </span>
            </div>
          </div>
        </div>

        {/* Process status donut */}
        <div className="card" style={s.gaugeCard}>
          <div style={s.cardHeader}>
            <Cpu size={14} color="var(--text-muted)" />
            <span style={s.cardTitle}>Process Status</span>
          </div>
          {statusData.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: 1 }}>
              <PieChart width={148} height={148}>
                <Pie data={statusData} cx={74} cy={74} innerRadius={44} outerRadius={68} dataKey="value" strokeWidth={0}>
                  {statusData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#F7F0E6" }} />
              </PieChart>
              <div style={s.legendGrid}>
                {statusData.map((d) => (
                  <div key={d.name} style={s.legendItem}>
                    <div style={{ width: 7, height: 7, borderRadius: "50%", background: d.color, flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>{d.name}</span>
                    <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)", marginLeft: "auto" }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p style={s.empty}>No data yet</p>
          )}
        </div>

        {/* Alert severity bars */}
        <div className="card" style={s.gaugeCard}>
          <div style={s.cardHeader}>
            <AlertTriangle size={14} color="var(--text-muted)" />
            <span style={s.cardTitle}>Alerts by Severity</span>
          </div>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "center" }}>
            <ResponsiveContainer width="100%" height={138}>
              <BarChart data={alertBarData} barSize={22} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {alertBarData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} fillOpacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 3: Risk distribution chart */}
      {riskSparkData.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ ...s.cardHeader, marginBottom: 12 }}>
            <TrendingUp size={14} color="var(--text-muted)" />
            <span style={s.cardTitle}>Top Processes by Risk Score</span>
          </div>
          <ResponsiveContainer width="100%" height={172}>
            <AreaChart data={riskSparkData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#FB923C" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#FB923C" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="risk" stroke="#FB923C" strokeWidth={2} fill="url(#riskGrad)" dot={{ fill: "#FB923C", r: 3, strokeWidth: 0 }} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Row 4: Recent Alerts + Top Risk Processes */}
      <div style={s.twoCol}>
        {/* Recent Alerts */}
        <div className="card">
          <div style={s.sectionHeader}>
            <div style={s.cardHeader}>
              <AlertTriangle size={14} color="var(--text-muted)" />
              <span style={s.cardTitle}>Recent Alerts</span>
            </div>
            <button className="btn btn-ghost" style={s.viewAllBtn} onClick={() => navigate("/alerts")}>
              View all
            </button>
          </div>
          {recentAlerts.length === 0 ? (
            <p style={s.empty}>No alerts - system looks clean</p>
          ) : (
            <div style={s.listWrap}>
              {recentAlerts.map((alert, i) => (
                <div
                  key={alert.id}
                  style={{ ...s.listRow, borderBottom: i < recentAlerts.length - 1 ? "1px solid var(--border)" : "none" }}
                  onClick={() => navigate("/alerts")}
                >
                  <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
                  <span style={s.listTitle}>{alert.title}</span>
                  <span style={s.listTime}>
                    {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Risk Processes */}
        <div className="card">
          <div style={s.sectionHeader}>
            <div style={s.cardHeader}>
              <Eye size={14} color="var(--text-muted)" />
              <span style={s.cardTitle}>Top Risk Processes</span>
            </div>
            <button className="btn btn-ghost" style={s.viewAllBtn} onClick={() => navigate("/processes")}>
              View all
            </button>
          </div>
          {topRiskProcesses.length === 0 ? (
            <p style={s.empty}>No high-risk processes detected</p>
          ) : (
            <div style={s.listWrap}>
              {topRiskProcesses.map((p, i) => {
                const barColor = p.risk_score >= 70 ? "#F87171" : p.risk_score >= 40 ? "#FBBF24" : "#FB923C";
                const scoreColor = p.risk_score >= 70 ? "#F87171" : p.risk_score >= 40 ? "#FBBF24" : "#FB923C";
                return (
                  <div
                    key={p.id}
                    style={{ ...s.listRow, borderBottom: i < topRiskProcesses.length - 1 ? "1px solid var(--border)" : "none" }}
                    onClick={() => navigate(`/processes/${p.id}`)}
                  >
                    <div style={s.riskBar}>
                      <div
                        style={{
                          width: `${Math.min(p.risk_score, 100)}%`,
                          background: barColor,
                          height: "100%",
                          borderRadius: 99,
                          transition: "width 0.3s ease",
                        }}
                      />
                    </div>
                    <span style={{ ...s.listTitle, fontFamily: "var(--font-mono)", fontSize: 12 }}>
                      {p.name}
                    </span>
                    <span style={{ ...s.listTime, fontWeight: 600, color: scoreColor }}>
                      {p.risk_score}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 24,
  },
  headerBadge: {
    display: "flex",
    alignItems: "center",
    gap: 7,
    padding: "8px 16px",
    background: "var(--bg-card)",
    border: "1px solid var(--border)",
    borderRadius: 999,
  },
  dot: {
    width: 7,
    height: 7,
    borderRadius: "50%",
    boxShadow: "0 0 6px currentColor",
  },
  pageTitle: {
    fontSize: 28,
    fontWeight: 700,
    letterSpacing: "-0.02em",
    marginBottom: 4,
  },
  pageSubtitle: {
    color: "var(--text-muted)",
    fontSize: 13,
  },
  statsGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: 12,
    marginBottom: 16,
  },
  statCard: {
    display: "flex",
    alignItems: "center",
    gap: 12,
    padding: "16px 18px",
  },
  statIconWrap: {
    width: 40,
    height: 40,
    borderRadius: 11,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },
  statValue: {
    fontSize: 24,
    fontWeight: 700,
    lineHeight: 1.1,
    letterSpacing: "-0.02em",
  },
  statLabel: {
    fontSize: 11,
    color: "var(--text-muted)",
    marginTop: 3,
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.04em",
  },
  threeCol: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
    gap: 16,
    marginBottom: 16,
  },
  gaugeCard: {
    display: "flex",
    flexDirection: "column",
    minHeight: 236,
    padding: "18px",
  },
  cardHeader: {
    display: "flex",
    alignItems: "center",
    gap: 7,
    marginBottom: 8,
  },
  cardTitle: {
    fontSize: 12,
    fontWeight: 600,
    color: "var(--text-secondary)",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
  },
  legendGrid: {
    display: "flex",
    flexDirection: "column",
    gap: 7,
    width: "100%",
    marginTop: 12,
  },
  legendItem: {
    display: "flex",
    alignItems: "center",
    gap: 7,
  },
  twoCol: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
    gap: 16,
    marginBottom: 14,
  },
  sectionHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 12,
  },
  viewAllBtn: {
    fontSize: 12,
    padding: "4px 12px",
  },
  listWrap: {
    display: "flex",
    flexDirection: "column",
    gap: 0,
  },
  listRow: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    cursor: "pointer",
    padding: "11px 0",
    borderBottom: "1px solid var(--border)",
    transition: "opacity 0.12s",
  },
  listTitle: {
    flex: 1,
    fontSize: 14,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  listTime: {
    fontSize: 12,
    color: "var(--text-muted)",
    whiteSpace: "nowrap",
  },
  riskBar: {
    width: 36,
    height: 4,
    background: "var(--border)",
    borderRadius: 99,
    flexShrink: 0,
    overflow: "hidden",
  },
  empty: {
    color: "var(--text-muted)",
    fontSize: 14,
    textAlign: "center",
    padding: "20px 0",
  },
};
