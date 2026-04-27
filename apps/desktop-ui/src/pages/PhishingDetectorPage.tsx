import { useEffect, useState } from "react";
import { AlertTriangle, ShieldCheck, X } from "lucide-react";

type ScanResult = {
  score: number;
  status: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
  reasons: string[];
  summary: string;
};

type HistoryItem = ScanResult & {
  sender: string;
  subject: string;
  body: string;
  display: string;
  time: string;
};

const STORAGE_KEY = "phishing_history";

export default function PhishingDetectorPage() {
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]") as HistoryItem[];
    setHistory(saved);
  }, []);

  const analyze = (messageSender: string, messageSubject: string, messageBody: string): ScanResult => {
    const lower = [messageSender, messageSubject, messageBody].join(" \n").toLowerCase();
    let score = 0;
    const reasons: string[] = [];

    const keywords = [
      "login",
      "verify",
      "account",
      "secure",
      "bank",
      "update",
      "password",
      "confirm",
      "urgent",
      "click",
      "payment",
      "invoice",
    ];

    keywords.forEach((word) => {
      if (lower.includes(word)) {
        score += 10;
        reasons.push(`Contains "${word}"`);
      }
    });

    if (/\.(ru|xyz|tk|ml|ga|cf)/.test(lower)) {
      score += 25;
      reasons.push("Suspicious domain (.ru/.xyz/etc)");
    }

    if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(lower)) {
      score += 30;
      reasons.push("Uses IP address instead of domain");
    }

    if (lower.length > 40) {
      score += 10;
      reasons.push("Unusually long URL");
    }

    if ((lower.match(/-/g) || []).length > 3) {
      score += 15;
      reasons.push("Too many hyphens (common phishing trick)");
    }

    if (
      lower.includes("@") &&
      (lower.includes("support") ||
        lower.includes("security") ||
        lower.includes("admin") ||
        lower.includes("helpdesk"))
    ) {
      score += 10;
      reasons.push("Impersonation-style email");
    }

    score = Math.min(score, 100);

    let status: ScanResult["status"] = "SAFE";
    if (score >= 70) status = "MALICIOUS";
    else if (score >= 35) status = "SUSPICIOUS";

    return {
      score,
      status,
      reasons,
      summary: generateSummary(status, reasons),
    };
  };

  const generateSummary = (status: ScanResult["status"], reasons: string[]) => {
    if (status === "SAFE") {
      return "This message appears low risk based on the sender, subject, and body. No strong phishing patterns were detected.";
    }

    if (status === "SUSPICIOUS") {
      return `This message is suspicious because it contains several warning signs: ${reasons
        .slice(0, 3)
        .join(", ")}. Review the sender and links carefully.`;
    }

    return `This message is likely malicious because it matches multiple phishing indicators, including ${reasons
      .slice(0, 3)
      .join(", ")}. Avoid clicking links or sharing credentials.`;
  };

  const handleScan = () => {
    if (!sender && !subject && !body) {
      return;
    }

    setLoading(true);

    window.setTimeout(() => {
      const scanResult = analyze(sender, subject, body);
      setResult(scanResult);

      const newItem: HistoryItem = {
        sender,
        subject,
        body,
        display: subject || sender || body.substring(0, 40),
        ...scanResult,
        time: new Date().toLocaleTimeString(),
      };

      const updated = [newItem, ...history].slice(0, 8);
      setHistory(updated);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));

      setLoading(false);
    }, 600);
  };

  const deleteItem = (index: number) => {
    const updated = history.filter((_, itemIndex) => itemIndex !== index);
    setHistory(updated);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  };

  const clearAll = () => {
    setHistory([]);
    localStorage.removeItem(STORAGE_KEY);
  };

  const getColor = (status: ScanResult["status"]) => {
    if (status === "MALICIOUS") return "#F87171";
    if (status === "SUSPICIOUS") return "#FBBF24";
    return "#4ADE80";
  };

  return (
    <div
      style={{
        width: "100%",
        maxWidth: "100%",
        minHeight: "100%",
        display: "flex",
        flexDirection: "column",
        gap: 18,
      }}
    >
      <div style={styles.pageHeader}>
        <div>
          <h1 style={styles.title}>Phishing Detector</h1>
          <p style={styles.subtitle}>
            Analyze the sender, subject, and body together for clearer phishing insights.
          </p>
        </div>
      </div>

      <div style={styles.card}>
        <div style={styles.formGrid}>
          <label style={styles.field}>
            <span style={styles.fieldLabel}>Sender</span>
            <input
              value={sender}
              onChange={(event) => setSender(event.target.value)}
              placeholder="sender@example.com"
              className="input"
              style={styles.fieldInput}
            />
          </label>

          <label style={styles.field}>
            <span style={styles.fieldLabel}>Subject</span>
            <input
              value={subject}
              onChange={(event) => setSubject(event.target.value)}
              placeholder="Subject line"
              className="input"
              style={styles.fieldInput}
            />
          </label>
        </div>

        <label style={{ ...styles.field, width: "100%" }}>
          <span style={styles.fieldLabel}>Message body</span>
          <textarea
            value={body}
            onChange={(event) => setBody(event.target.value)}
            placeholder="Paste the full email content here"
            className="input"
            style={styles.bodyInput}
          />
        </label>

        <div style={styles.actionsRow}>
          <button className="btn btn-primary" onClick={handleScan} disabled={loading}>
            Scan message
          </button>
          <span style={styles.note}>
            The analysis uses sender, subject, and body together for better context.
          </span>
        </div>

        {loading && (
          <p style={styles.loading}>Scanning the message for phishing indicators...</p>
        )}

        {result && (
          <div style={styles.resultBox}>
            <div style={styles.header}>
              {result.status === "SAFE" ? (
                <ShieldCheck size={18} color="#4ADE80" />
              ) : (
                <AlertTriangle size={18} color={getColor(result.status)} />
              )}
              <span style={{ color: getColor(result.status), fontWeight: 700 }}>
                {result.status}
              </span>
            </div>

            <div style={styles.barWrap}>
              <div
                style={{
                  ...styles.barFill,
                  width: `${Math.min(result.score, 100)}%`,
                  background: getColor(result.status),
                }}
              />
            </div>

            <p style={styles.score}>{result.score}% Risk Score</p>

            <ul style={styles.reasons}>
              {result.reasons.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>

            <div style={styles.summaryBox}>
              <h3 style={styles.summaryTitle}>Summary</h3>
              <p style={styles.summaryText}>{result.summary}</p>
            </div>
          </div>
        )}

        {history.length > 0 && (
          <div style={styles.historySection}>
            <div style={styles.historyHeader}>
              <h3>Recent Scans</h3>
              <button onClick={clearAll} style={styles.clearBtn}>
                Clear All
              </button>
            </div>

            {history.map((item, index) => (
              <div key={`${item.time}-${index}`} style={styles.historyItem}>
                <div>
                  <p style={styles.historyText}>{item.display}</p>
                  <p style={styles.muted}>{item.time}</p>
                </div>

                <div style={styles.historyRight}>
                  <span style={{ color: getColor(item.status) }}>{item.score}%</span>

                  <X
                    size={16}
                    style={styles.deleteIcon}
                    onClick={() => deleteItem(index)}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  pageHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: 12,
  },
  title: { fontSize: 28, fontWeight: 700, marginBottom: 6 },
  subtitle: {
    color: "var(--text-muted)",
    fontSize: 13,
    marginTop: 0,
  },
  card: {
    padding: 20,
    borderRadius: 14,
    border: "1px solid #48423B",
    background: "linear-gradient(145deg, #2A2520, #1F1B18)",
  },
  formGrid: {
    display: "grid",
    gap: 16,
    gridTemplateColumns: "1fr 1fr",
    marginBottom: 18,
  },
  loading: { color: "#aaa", fontSize: 12 },
  field: { display: "flex", flexDirection: "column", gap: 8 },
  fieldLabel: { fontSize: 12, color: "var(--text-muted)", fontWeight: 600 },
  fieldInput: { width: "100%", minHeight: 40 },
  bodyInput: {
    width: "100%",
    minHeight: 180,
    resize: "vertical",
    padding: 14,
    fontFamily: "inherit",
    fontSize: 13,
    lineHeight: 1.6,
  },
  actionsRow: {
    display: "flex",
    alignItems: "center",
    gap: 14,
    marginTop: 16,
    flexWrap: "wrap",
  },
  note: { color: "var(--text-muted)", fontSize: 12 },
  resultBox: {
    marginTop: 14,
    padding: 14,
    borderRadius: 12,
    border: "1px solid #333",
    background: "#1F1B18",
  },
  header: { display: "flex", gap: 8, alignItems: "center" },
  barWrap: {
    height: 6,
    background: "#333",
    borderRadius: 999,
    margin: "6px 0",
  },
  barFill: { height: "100%", borderRadius: 999 },
  score: { fontSize: 11, color: "#aaa" },
  reasons: {
    marginTop: 10,
    paddingLeft: 18,
    fontSize: 12,
    color: "#ccc",
  },
  summaryBox: {
    marginTop: 14,
    padding: 14,
    borderRadius: 12,
    background: "rgba(255,255,255,0.04)",
    border: "1px solid rgba(255,255,255,0.08)",
  },
  summaryTitle: {
    margin: 0,
    fontSize: 13,
    fontWeight: 600,
    color: "var(--text-primary)",
  },
  summaryText: {
    margin: "8px 0 0",
    fontSize: 12,
    lineHeight: 1.7,
    color: "#d0d0d0",
  },
  historySection: { marginTop: 20 },
  historyHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 8,
  },
  clearBtn: {
    background: "transparent",
    border: "1px solid #444",
    borderRadius: 6,
    padding: "4px 10px",
    color: "#aaa",
    cursor: "pointer",
  },
  historyItem: {
    background: "#1F1B18",
    border: "1px solid #333",
    borderRadius: 10,
    padding: 12,
    marginTop: 8,
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  },
  historyText: { fontWeight: 600 },
  historyRight: {
    display: "flex",
    alignItems: "center",
    gap: 10,
  },
  deleteIcon: {
    cursor: "pointer",
    color: "#888",
  },
  muted: { fontSize: 11, color: "#888" },
};
