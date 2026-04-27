import { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useAppStore } from "@/store";
import type { ProcessRecord, ProcessMetric } from "@/types";
import type { AiChatMessage } from "@/lib/invoke";
import {
  getProcessDetails,
  getProcessMetrics,
  killProcess,
  trustProcess,
  askAiAboutProcess,
} from "@/lib/invoke";
import { formatDistanceToNow, format } from "date-fns";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { ArrowLeft, Skull, ShieldCheck, AlertTriangle, Bot, Send } from "lucide-react";

export default function ProcessDetailPage() {
  const { processId } = useParams<{ processId: string }>();
  const navigate = useNavigate();
  const { getAlertsForProcess, removeProcess } = useAppStore();

  const [process, setProcess] = useState<ProcessRecord | null>(null);
  const alerts = processId ? getAlertsForProcess(processId) : [];

  const [metrics, setMetrics] = useState<ProcessMetric[]>([]);
  const [loading, setLoading] = useState(true);

  const [aiOpen, setAiOpen] = useState(false);
  const [aiMessages, setAiMessages] = useState<{ role: "user" | "ai"; text: string }[]>([]);
  const [aiInput, setAiInput] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const aiEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!processId) return;
    setLoading(true);
    Promise.all([
      getProcessDetails(processId).then(setProcess),
      getProcessMetrics(processId, 60).then(setMetrics),
    ])
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [processId]);

  const handleAskAi = async () => {
    if (!processId || !aiInput.trim() || aiLoading) return;
    const question = aiInput.trim();
    const history: AiChatMessage[] = aiMessages
      .slice(-6)
      .map((message) => ({
        role: message.role === "ai" ? "assistant" : "user",
        content: message.text,
      }));
    setAiInput("");
    setAiMessages((m) => [...m, { role: "user", text: question }]);
    setAiLoading(true);
    try {
      const answer = await askAiAboutProcess(processId, question, history);
      setAiMessages((m) => [...m, { role: "ai", text: answer }]);
    } catch (err) {
      setAiMessages((m) => [...m, { role: "ai", text: `Error: ${err}` }]);
    } finally {
      setAiLoading(false);
      setTimeout(() => aiEndRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
    }
  };

  const handleKill = async () => {
    if (!process) return;
    if (!confirm(`Kill process ${process.name} (PID ${process.pid})?`)) return;
    try {
      await killProcess(process.pid, process.id);
      removeProcess(process.id);
      navigate("/processes");
    } catch (err) {
      alert(`Failed to kill process: ${err}`);
    }
  };

  const handleTrust = async () => {
    if (!process) return;
    try {
      await trustProcess(process.id, process.file_hash ? "file_hash" : "exe_path", process.file_hash ?? process.exe_path ?? "");
      alert(`"${process.name}" has been marked as trusted and will no longer generate alerts.`);
    } catch (err) {
      alert(`Failed to trust process: ${err}`);
    }
  };

  if (loading && !process) {
    return (
      <div>
        <button className="btn btn-ghost" onClick={() => navigate("/processes")}>
          <ArrowLeft size={14} /> Back
        </button>
        <p style={{ marginTop: 24, color: "var(--text-muted)" }}>Loading…</p>
      </div>
    );
  }

  if (!loading && !process) {
    return (
      <div>
        <button className="btn btn-ghost" onClick={() => navigate("/processes")}>
          <ArrowLeft size={14} /> Back
        </button>
        <p style={{ marginTop: 24, color: "var(--text-muted)" }}>Process not found.</p>
      </div>
    );
  }

  // At this point process is guaranteed non-null (loading spinner shown above otherwise)
  const proc = process!;

  const chartData = metrics.map((m) => ({
    time: format(new Date(m.timestamp), "HH:mm:ss"),
    cpu: m.cpu_percent,
    mem: (m.memory_bytes / 1024 / 1024).toFixed(1),
    netSent: (m.network_bytes_sent / 1024).toFixed(1),
    netRecv: (m.network_bytes_received / 1024).toFixed(1),
  }));

  return (
    <div>
      <button
        className="btn btn-ghost"
        style={{ marginBottom: 16 }}
        onClick={() => navigate("/processes")}
      >
        <ArrowLeft size={14} /> Back to Processes
      </button>

      <div style={styles.header}>
        <div>
          <h1 style={styles.title} className="mono">
            {proc.name}
          </h1>
          <p style={styles.subtitle}>
            PID {proc.pid}
            {proc.parent_pid != null && ` · Parent PID ${proc.parent_pid}`}
            {proc.user_name && ` · ${proc.user_name}`}
          </p>
        </div>
        <div style={styles.actions}>
          <button className="btn btn-ghost" onClick={() => setAiOpen((v) => !v)}>
            <Bot size={14} /> Ask AI
          </button>
          <button className="btn btn-ghost" onClick={handleTrust}>
            <ShieldCheck size={14} /> Trust
          </button>
          <button className="btn btn-danger" onClick={handleKill}>
            <Skull size={14} /> Kill
          </button>
        </div>
      </div>

      {/* Meta grid */}
      <div style={styles.metaGrid}>
        {[
          ["Status", proc.current_status],
          ["Risk Score", proc.risk_score],
          ["Signer", proc.signer_status],
          ["Path Category", proc.path_category],
          ["Integrity Level", proc.integrity_level ?? "—"],
          [
            "First Seen",
            formatDistanceToNow(new Date(proc.first_seen_at), {
              addSuffix: true,
            }),
          ],
        ].map(([label, value]) => (
          <div key={label} className="card" style={styles.metaCard}>
            <div style={styles.metaLabel}>{label}</div>
            <div style={styles.metaValue}>{value}</div>
          </div>
        ))}
      </div>

      {/* Exe path */}
      {proc.exe_path && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={styles.metaLabel}>Executable Path</div>
          <div className="mono" style={{ fontSize: 12, marginTop: 4, wordBreak: "break-all" }}>
            {proc.exe_path}
          </div>
        </div>
      )}

      {/* Command line */}
      {proc.command_line && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={styles.metaLabel}>Command Line</div>
          <div
            className="mono"
            style={{
              fontSize: 12,
              marginTop: 4,
              wordBreak: "break-all",
              color: "var(--text-secondary)",
            }}
          >
            {proc.command_line}
          </div>
        </div>
      )}

      {/* Charts */}
      {!loading && chartData.length > 0 && (
        <div style={styles.chartsGrid}>
          <div className="card">
            <h2 style={styles.chartTitle}>CPU %</h2>
            <ResponsiveContainer width="100%" height={140}>
              <LineChart data={chartData}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                <XAxis dataKey="time" tick={{ fontSize: 9, fill: "var(--text-muted)" }} />
                <YAxis tick={{ fontSize: 9, fill: "var(--text-muted)" }} domain={[0, 100]} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line
                  type="monotone"
                  dataKey="cpu"
                  stroke="var(--color-blue)"
                  dot={false}
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="card">
            <h2 style={styles.chartTitle}>Memory (MB)</h2>
            <ResponsiveContainer width="100%" height={140}>
              <LineChart data={chartData}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                <XAxis dataKey="time" tick={{ fontSize: 9, fill: "var(--text-muted)" }} />
                <YAxis tick={{ fontSize: 9, fill: "var(--text-muted)" }} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line
                  type="monotone"
                  dataKey="mem"
                  stroke="var(--color-purple)"
                  dot={false}
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="card">
            <h2 style={styles.chartTitle}>Network KB (sent / recv)</h2>
            <ResponsiveContainer width="100%" height={140}>
              <LineChart data={chartData}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                <XAxis dataKey="time" tick={{ fontSize: 9, fill: "var(--text-muted)" }} />
                <YAxis tick={{ fontSize: 9, fill: "var(--text-muted)" }} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line
                  type="monotone"
                  dataKey="netSent"
                  stroke="var(--color-green)"
                  dot={false}
                  strokeWidth={2}
                  name="Sent"
                />
                <Line
                  type="monotone"
                  dataKey="netRecv"
                  stroke="var(--color-orange)"
                  dot={false}
                  strokeWidth={2}
                  name="Recv"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* AI Assistant Panel */}
      {aiOpen && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h2 style={{ ...styles.chartTitle, marginBottom: 12 }}>
            <Bot size={14} style={{ marginRight: 6, color: "var(--color-blue)" }} />
            Ask AI about {proc.name}
          </h2>

          {/* Suggested questions */}
          {aiMessages.length === 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}>
              {[
                "What is this process?",
                "Why is this flagged?",
                "Is it safe to kill?",
                "What should I do next?",
              ].map((q) => (
                <button
                  key={q}
                  className="btn btn-ghost"
                  style={{ fontSize: 12, padding: "4px 10px" }}
                  onClick={() => { setAiInput(q); }}
                >
                  {q}
                </button>
              ))}
            </div>
          )}

          {/* Messages */}
          <div style={{ maxHeight: 320, overflowY: "auto", marginBottom: 10, display: "flex", flexDirection: "column", gap: 8 }}>
            {aiMessages.map((msg, i) => (
              <div
                key={i}
                style={{
                  alignSelf: msg.role === "user" ? "flex-end" : "flex-start",
                  maxWidth: "82%",
                  padding: "8px 12px",
                  borderRadius: 8,
                  fontSize: 13,
                  lineHeight: 1.5,
                  background: msg.role === "user" ? "rgba(59,130,246,0.15)" : "var(--bg-secondary)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border)",
                  whiteSpace: "pre-wrap",
                }}
              >
                {msg.text}
              </div>
            ))}
            {aiLoading && (
              <div style={{ alignSelf: "flex-start", color: "var(--text-muted)", fontSize: 12, padding: "4px 8px" }}>
                Thinking…
              </div>
            )}
            <div ref={aiEndRef} />
          </div>

          {/* Input row */}
          <div style={{ display: "flex", gap: 8 }}>
            <input
              className="input"
              style={{ flex: 1 }}
              placeholder="Ask a question about this process…"
              value={aiInput}
              onChange={(e) => setAiInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAskAi()}
              disabled={aiLoading}
            />
            <button className="btn btn-primary" onClick={handleAskAi} disabled={aiLoading || !aiInput.trim()}>
              <Send size={14} />
            </button>
          </div>
        </div>
      )}

      {/* Alerts for this process */}
      {alerts.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h2 style={{ ...styles.chartTitle, marginBottom: 12 }}>
            <AlertTriangle size={14} style={{ marginRight: 6, color: "var(--color-red)" }} />
            Alerts ({alerts.length})
          </h2>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Risk</th>
                  <th>Time</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                    </td>
                    <td>{a.title}</td>
                    <td>{a.risk_score}</td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {formatDistanceToNow(new Date(a.timestamp), { addSuffix: true })}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-secondary)" }}>{a.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

const tooltipStyle: React.CSSProperties = {
  background: "var(--bg-card)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  fontSize: 11,
};

const styles: Record<string, React.CSSProperties> = {
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 16,
  },
  title: {
    fontSize: 20,
    fontWeight: 700,
  },
  subtitle: {
    color: "var(--text-muted)",
    fontSize: 12,
    marginTop: 4,
  },
  actions: {
    display: "flex",
    gap: 8,
  },
  metaGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))",
    gap: 10,
    marginBottom: 14,
  },
  metaCard: {
    padding: 12,
  },
  metaLabel: {
    fontSize: 11,
    color: "var(--text-muted)",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    marginBottom: 4,
  },
  metaValue: {
    fontSize: 14,
    fontWeight: 600,
  },
  chartsGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr 1fr",
    gap: 12,
    marginBottom: 16,
  },
  chartTitle: {
    fontSize: 13,
    fontWeight: 600,
    marginBottom: 8,
    display: "flex",
    alignItems: "center",
  },
};
