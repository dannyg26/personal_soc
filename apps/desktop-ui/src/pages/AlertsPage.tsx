import { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/store";
import type { Alert, AlertStatus, PasswordHealthAlert, Severity } from "@/types";
import { getPasswordHealthAlert, updateAlertStatus } from "@/lib/invoke";
import { formatDistanceToNow } from "date-fns";
import { useNavigate } from "react-router-dom";
import { ChevronDown, ChevronRight } from "lucide-react";

const PASSWORD_ALERT_ID = "threat-guard-password-health-alert";

type AlertsListItem = Alert & {
  source_kind?: "monitor" | "password_health";
};

function buildPasswordAlert(alert: PasswordHealthAlert): AlertsListItem {
  return {
    id: PASSWORD_ALERT_ID,
    process_id: "",
    timestamp: alert.last_checked_at,
    severity: alert.severity,
    title: alert.title,
    summary: `${alert.summary}\n\nRecommended action: ${alert.recommendation}`,
    status: "open",
    risk_score: alert.risk_score,
    triggered_rules: [
      {
        rule_key: "password_health",
        explanation: alert.summary,
        evidence: {
          compromised_count: alert.compromised_count,
          weak_compromised_count: alert.weak_compromised_count,
          affected_sites: alert.affected_sites,
        },
        weight: alert.risk_score,
      },
    ],
    source_kind: "password_health",
  };
}

export default function AlertsPage() {
  const { alerts, setAlerts } = useAppStore();
  const navigate = useNavigate();
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "">("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "">("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [passwordAlert, setPasswordAlert] = useState<PasswordHealthAlert | null>(null);

  useEffect(() => {
    const loadPasswordAlert = async () => {
      try {
        const alert = await getPasswordHealthAlert();
        setPasswordAlert(alert.has_alert ? alert : null);
      } catch (err) {
        console.error("Failed to load password health alert:", err);
        setPasswordAlert(null);
      }
    };

    void loadPasswordAlert();
    const interval = window.setInterval(() => {
      void loadPasswordAlert();
    }, 300000);

    return () => window.clearInterval(interval);
  }, []);

  const allAlerts = useMemo<AlertsListItem[]>(() => {
    const items: AlertsListItem[] = alerts.map((alert) => ({
      ...alert,
      source_kind: "monitor",
    }));
    if (passwordAlert?.has_alert) {
      items.push(buildPasswordAlert(passwordAlert));
    }

    return items;
  }, [alerts, passwordAlert]);

  const filtered = allAlerts
    .filter((a) => (!statusFilter || a.status === statusFilter) && (!severityFilter || a.severity === severityFilter))
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  const handleStatus = async (alert: Alert, newStatus: AlertStatus) => {
    try {
      await updateAlertStatus(alert.id, newStatus);
      setAlerts(alerts.map((a) => (a.id === alert.id ? { ...a, status: newStatus } : a)));
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div>
      <h1 style={styles.pageTitle}>Alerts</h1>

      <div style={styles.toolbar}>
        <select
          className="input"
          style={{ width: 150 }}
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as AlertStatus | "")}
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="ignored">Ignored</option>
          <option value="resolved">Resolved</option>
        </select>
        <select
          className="input"
          style={{ width: 150 }}
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | "")}
        >
          <option value="">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <span style={styles.count}>{filtered.length} alerts</span>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {filtered.length === 0 ? (
          <p style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
            No alerts match your filters
          </p>
        ) : (
          filtered.map((alert) => (
            <div key={alert.id} style={styles.alertBlock}>
              {/* Header row */}
              <div
                style={styles.alertHeader}
                onClick={() => setExpandedId(expandedId === alert.id ? null : alert.id)}
              >
                <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>
                  {expandedId === alert.id ? (
                    <ChevronDown size={14} />
                  ) : (
                    <ChevronRight size={14} />
                  )}
                </span>
                <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
                <span style={styles.alertTitle}>{alert.title}</span>
                <span style={styles.alertRisk}>risk: {alert.risk_score}</span>
                <span style={styles.alertTime}>
                  {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
                </span>
                <span
                  style={{
                    ...styles.alertStatus,
                    color:
                      alert.status === "open"
                        ? "var(--color-red)"
                        : "var(--text-muted)",
                  }}
                >
                  {alert.status}
                </span>
              </div>

              {/* Expanded detail */}
              {expandedId === alert.id && (
                <div style={styles.alertDetail}>
                  <p style={styles.alertSummary}>{alert.summary}</p>

                  {/* Triggered rules */}
                  {alert.triggered_rules.length > 0 && (
                    <div style={{ marginTop: 10 }}>
                      <div style={styles.rulesTitle}>Triggered Rules</div>
                      {alert.triggered_rules.map((r) => (
                        <div key={r.rule_key} style={styles.ruleRow}>
                          <span className="mono" style={styles.ruleKey}>
                            {r.rule_key}
                          </span>
                          <span style={styles.ruleExplanation}>{r.explanation}</span>
                          <span style={styles.ruleWeight}>weight: {r.weight}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Actions */}
                  <div style={styles.alertActions}>
                    {alert.source_kind === "password_health" ? (
                      <button
                        className="btn btn-primary"
                        onClick={() => navigate("/password-manager")}
                      >
                        Review in Password Manager
                      </button>
                    ) : (
                      <button
                        className="btn btn-ghost"
                        onClick={() => navigate(`/processes/${alert.process_id}`)}
                      >
                        View Process
                      </button>
                    )}
                    {alert.source_kind !== "password_health" && alert.status === "open" && (
                      <>
                        <button
                          className="btn btn-ghost"
                          onClick={() => handleStatus(alert, "acknowledged")}
                        >
                          Acknowledge
                        </button>
                        <button
                          className="btn btn-ghost"
                          onClick={() => handleStatus(alert, "ignored")}
                        >
                          Ignore
                        </button>
                      </>
                    )}
                    {alert.source_kind !== "password_health" && alert.status !== "resolved" && (
                      <button
                        className="btn btn-primary"
                        onClick={() => handleStatus(alert, "resolved")}
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  pageTitle: {
    fontSize: 22,
    fontWeight: 700,
    marginBottom: 16,
  },
  toolbar: {
    display: "flex",
    gap: 10,
    alignItems: "center",
    marginBottom: 14,
  },
  count: {
    fontSize: 12,
    color: "var(--text-muted)",
    marginLeft: "auto",
  },
  alertBlock: {
    borderBottom: "1px solid var(--border)",
  },
  alertHeader: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "10px 14px",
    cursor: "pointer",
  },
  alertTitle: {
    flex: 1,
    fontSize: 13,
    fontWeight: 500,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  alertRisk: {
    fontSize: 11,
    color: "var(--text-muted)",
    whiteSpace: "nowrap",
  },
  alertTime: {
    fontSize: 11,
    color: "var(--text-muted)",
    whiteSpace: "nowrap",
  },
  alertStatus: {
    fontSize: 11,
    fontWeight: 600,
    textTransform: "capitalize",
    whiteSpace: "nowrap",
  },
  alertDetail: {
    padding: "0 16px 14px 36px",
  },
  alertSummary: {
    fontSize: 13,
    color: "var(--text-secondary)",
    lineHeight: 1.6,
    whiteSpace: "pre-line",
  },
  rulesTitle: {
    fontSize: 11,
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    color: "var(--text-muted)",
    marginBottom: 6,
  },
  ruleRow: {
    display: "flex",
    alignItems: "baseline",
    gap: 8,
    fontSize: 12,
    padding: "3px 0",
    borderTop: "1px solid var(--border)",
  },
  ruleKey: {
    color: "var(--color-blue)",
    fontSize: 11,
    flexShrink: 0,
  },
  ruleExplanation: {
    flex: 1,
    color: "var(--text-secondary)",
  },
  ruleWeight: {
    color: "var(--text-muted)",
    fontSize: 11,
    flexShrink: 0,
  },
  alertActions: {
    display: "flex",
    gap: 8,
    marginTop: 12,
  },
};
