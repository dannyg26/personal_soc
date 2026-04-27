import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { open } from "@tauri-apps/plugin-shell";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  Globe,
  History,
  Link2,
  LoaderCircle,
  Lock,
  LockOpen,
  Radar,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import { checkUrl } from "@/lib/invoke";
import type { UrlScanResult } from "@/types";

type ScanHistoryItem = {
  input: string;
  domain: string;
  verdict: UrlScanResult["verdict"];
  local_risk_score: number;
  timestamp: string;
};

const HISTORY_KEY = "malicious_link_history_v2";
const EXAMPLES = [
  "https://accounts-secure-paypal-login.example.com/verify",
  "http://185.14.31.44/login",
  "https://openai.com",
];

const VERDICT_STYLES = {
  MALICIOUS: {
    color: "var(--color-red)",
    surface: "rgba(248,113,113,0.12)",
    border: "rgba(248,113,113,0.24)",
    icon: AlertTriangle,
    copy: "Do not open this link until it has been verified.",
  },
  SUSPICIOUS: {
    color: "var(--color-yellow)",
    surface: "rgba(251,191,36,0.12)",
    border: "rgba(251,191,36,0.24)",
    icon: ShieldAlert,
    copy: "Treat this link carefully and verify the sender or destination first.",
  },
  CLEAN: {
    color: "var(--color-green)",
    surface: "rgba(74,222,128,0.12)",
    border: "rgba(74,222,128,0.24)",
    icon: ShieldCheck,
    copy: "No major issues were detected in the available reputation and heuristic checks.",
  },
} as const;

const SCAN_TARGET_LABELS = {
  url: "URL",
  domain: "domain",
  ip_address: "IP address",
} as const;

export default function MaliciousLinkDetectorPage() {
  const navigate = useNavigate();
  const [input, setInput] = useState("");
  const [result, setResult] = useState<UrlScanResult | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(HISTORY_KEY);
      if (saved) {
        setHistory(JSON.parse(saved));
      }
    } catch (err) {
      console.error("Failed to load malicious link history:", err);
    }
  }, []);

  useEffect(() => {
    if (!copied) {
      return;
    }

    const timer = window.setTimeout(() => setCopied(false), 1400);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const handleScan = async (value = input) => {
    const trimmed = value.trim();
    if (!trimmed) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const nextResult = await checkUrl(trimmed);
      setInput(trimmed);
      setResult(nextResult);

      const nextHistoryItem: ScanHistoryItem = {
        input: trimmed,
        domain: nextResult.domain,
        verdict: nextResult.verdict,
        local_risk_score: nextResult.local_risk_score,
        timestamp: new Date().toLocaleString(),
      };

      setHistory((current) => {
        const updated = [
          nextHistoryItem,
          ...current.filter((item) => item.input !== trimmed),
        ].slice(0, 8);

        localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
        return updated;
      });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : typeof err === "string" ? err : "Scan failed.";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!result) {
      return;
    }

    try {
      await navigator.clipboard.writeText(result.normalized_url);
      setCopied(true);
    } catch (err) {
      console.error("Failed to copy URL:", err);
    }
  };

  const handleClearHistory = () => {
    setHistory([]);
    localStorage.removeItem(HISTORY_KEY);
  };

  const verdict = result?.verdict ?? "CLEAN";
  const verdictStyle = VERDICT_STYLES[verdict];
  const VerdictIcon = verdictStyle.icon;
  const targetLabel = result ? SCAN_TARGET_LABELS[result.scan_target] : "link";
  const verdictCopy = result
    ? result.verdict_source === "virustotal"
      ? `Verdict sourced from VirusTotal ${targetLabel} reputation data.`
      : verdictStyle.copy
    : verdictStyle.copy;
  const vtSummaryCount = result?.virustotal
    ? result.virustotal.malicious +
      result.virustotal.suspicious +
      result.virustotal.harmless +
      result.virustotal.undetected
    : 0;

  return (
    <div style={styles.page}>
      <div style={styles.hero}>
        <div>
          <div style={styles.eyebrow}>
            <Sparkles size={13} color="var(--color-blue)" />
            <span>Security Tooling</span>
          </div>
          <h1 style={styles.title}>Malicious Link Detector</h1>
          <p style={styles.subtitle}>
            Scan URLs, domains, and IP addresses with VirusTotal-backed reputation lookups plus local heuristic context.
          </p>
        </div>

        <div style={styles.heroBadge}>
          <Radar size={14} color="var(--color-blue)" />
          <span>VirusTotal-backed scans</span>
        </div>
      </div>

      <div style={styles.topGrid}>
        <div className="card" style={styles.inputCard}>
            <div style={styles.sectionHeader}>
              <div style={styles.cardHeading}>
                <Link2 size={15} color="var(--text-muted)" />
                <span style={styles.cardLabel}>Scan Link</span>
              </div>
              <span style={styles.helperText}>Paste a URL, domain, or IP address</span>
            </div>

          <div style={styles.inputRow}>
            <input
              className="input"
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => event.key === "Enter" && void handleScan()}
              placeholder="https://example.com/login"
              style={{ flex: 1 }}
            />
            <button className="btn btn-primary" onClick={() => void handleScan()} disabled={loading}>
              {loading ? (
                <>
                  <LoaderCircle size={15} style={styles.spinner} />
                  Scanning
                </>
              ) : (
                <>
                  <Radar size={15} />
                  Scan
                </>
              )}
            </button>
          </div>

          <div style={styles.exampleRow}>
            {EXAMPLES.map((example) => (
              <button
                key={example}
                className="btn btn-ghost"
                style={styles.exampleButton}
                onClick={() => {
                  setInput(example);
                  void handleScan(example);
                }}
                disabled={loading}
              >
                {example}
              </button>
            ))}
          </div>

          {error && (
            <div style={styles.errorBox}>
              <AlertTriangle size={15} color="var(--color-red)" />
              <span>{error}</span>
            </div>
          )}

          <div style={styles.infoStrip}>
            <div style={styles.infoItem}>
              <Globe size={14} color="var(--color-blue)" />
              <span>VirusTotal matches URL, domain, and IP inputs to the right report type</span>
            </div>
            <div style={styles.infoItem}>
              <ShieldCheck size={14} color="var(--color-green)" />
              <span>Local heuristics stay visible as fallback context</span>
            </div>
          </div>
        </div>

        <div className="card" style={styles.historyCard}>
          <div style={styles.sectionHeader}>
            <div style={styles.cardHeading}>
              <History size={15} color="var(--text-muted)" />
              <span style={styles.cardLabel}>Recent Scans</span>
            </div>
            <div style={styles.headerActions}>
              <span style={styles.helperText}>{history.length} saved locally</span>
              <button
                className="btn btn-ghost"
                style={styles.clearHistoryButton}
                onClick={handleClearHistory}
                disabled={history.length === 0}
              >
                <Trash2 size={13} />
                Clear history
              </button>
            </div>
          </div>

          {history.length === 0 ? (
            <p style={styles.emptyCopy}>Your recent malicious-link checks will appear here.</p>
          ) : (
            <div style={styles.historyList}>
              {history.map((item) => (
                <button
                  key={`${item.input}-${item.timestamp}`}
                  style={styles.historyItem}
                  onClick={() => {
                    setInput(item.input);
                    void handleScan(item.input);
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <p style={styles.historyInput}>{item.input}</p>
                    <p style={styles.historyMeta}>{item.timestamp}</p>
                  </div>
                  <div style={styles.historyRight}>
                    <span
                      style={{
                        ...styles.historyScore,
                        color: VERDICT_STYLES[item.verdict].color,
                      }}
                    >
                      {item.local_risk_score}
                    </span>
                    <span style={styles.historyDomain}>{item.domain}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={styles.statGrid}>
        <div className="card" style={styles.statCard}>
          <p style={styles.statLabel}>Verdict</p>
          <div style={{ ...styles.statValueRow, color: verdictStyle.color }}>
            <VerdictIcon size={18} />
            <span style={styles.statValue}>{verdict}</span>
          </div>
        </div>

        <div className="card" style={styles.statCard}>
          <p style={styles.statLabel}>Local Risk</p>
          <div style={styles.statValueRow}>
            <span style={{ ...styles.statValue, color: verdictStyle.color }}>
              {result ? `${result.local_risk_score}/100` : "--"}
            </span>
          </div>
        </div>

        <div className="card" style={styles.statCard}>
          <p style={styles.statLabel}>Transport</p>
          <div style={styles.statValueRow}>
            {result?.uses_https ? (
              <>
                <Lock size={16} color="var(--color-green)" />
                <span style={styles.statValue}>HTTPS</span>
              </>
            ) : (
              <>
                <LockOpen size={16} color={result ? "var(--color-yellow)" : "var(--text-muted)"} />
                <span style={styles.statValue}>{result ? "No HTTPS" : "--"}</span>
              </>
            )}
          </div>
        </div>

        <div className="card" style={styles.statCard}>
          <p style={styles.statLabel}>Host Type</p>
          <div style={styles.statValueRow}>
            {result?.is_ip_address ? (
              <>
                <Server size={16} color="var(--color-red)" />
                <span style={styles.statValue}>IP Address</span>
              </>
            ) : (
              <>
                <Globe size={16} color={result ? "var(--color-blue)" : "var(--text-muted)"} />
                <span style={styles.statValue}>{result ? "Domain" : "--"}</span>
              </>
            )}
          </div>
        </div>
      </div>

      {result && (
        <div style={styles.resultGrid}>
          <div className="card" style={styles.primaryResultCard}>
            <div
              style={{
                ...styles.verdictBanner,
                background: verdictStyle.surface,
                borderColor: verdictStyle.border,
              }}
            >
              <div style={styles.verdictBannerLeft}>
                <VerdictIcon size={18} color={verdictStyle.color} />
                <div>
                  <p style={{ ...styles.bannerTitle, color: verdictStyle.color }}>{result.verdict}</p>
                  <p style={styles.bannerCopy}>{verdictCopy}</p>
                </div>
              </div>
              <button className="btn btn-ghost" style={styles.copyButton} onClick={handleCopy}>
                <Copy size={14} />
                {copied ? "Copied" : "Copy URL"}
              </button>
            </div>

            <div style={styles.progressWrap}>
              <div style={styles.progressTrack}>
                <div
                  style={{
                    ...styles.progressFill,
                    width: `${Math.min(result.local_risk_score, 100)}%`,
                    background: verdictStyle.color,
                  }}
                />
              </div>
              <div style={styles.progressMeta}>
                <span>{result.local_risk_score}% local risk score</span>
                <span>{result.url_length} chars</span>
              </div>
            </div>

            <div style={styles.detailGrid}>
              <div style={styles.detailCard}>
                <p style={styles.detailLabel}>Normalized URL</p>
                <p style={styles.detailValueMono}>{result.normalized_url}</p>
              </div>

              <div style={styles.detailCard}>
                <p style={styles.detailLabel}>Host</p>
                <p style={styles.detailValue}>{result.domain}</p>
                <p style={styles.detailMeta}>
                  {result.subdomain_depth > 0
                    ? `${result.subdomain_depth} nested subdomains`
                    : "Primary domain only"}
                </p>
              </div>
            </div>

            <div style={styles.sectionBlock}>
              <div style={styles.cardHeading}>
                <ShieldAlert size={15} color="var(--text-muted)" />
                <span style={styles.cardLabel}>Heuristic Findings</span>
              </div>
              <div style={styles.findingList}>
                {result.heuristics.map((item) => (
                  <div key={item} style={styles.findingItem}>
                    {result.verdict === "CLEAN" ? (
                      <CheckCircle2 size={14} color="var(--color-green)" />
                    ) : (
                      <AlertTriangle size={14} color={verdictStyle.color} />
                    )}
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={styles.sectionBlock}>
              <div style={styles.cardHeading}>
                <Sparkles size={15} color="var(--text-muted)" />
                <span style={styles.cardLabel}>Keyword Signals</span>
              </div>
              {result.suspicious_keywords.length === 0 ? (
                <p style={styles.emptyCopy}>No suspicious keywords were detected in the submitted input.</p>
              ) : (
                <div style={styles.keywordWrap}>
                  {result.suspicious_keywords.map((keyword) => (
                    <span key={keyword} style={styles.keywordChip}>
                      {keyword}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="card" style={styles.sideCard}>
            <div style={styles.sectionHeader}>
              <div style={styles.cardHeading}>
                <Radar size={15} color="var(--text-muted)" />
                <span style={styles.cardLabel}>Threat Intel</span>
              </div>
              <span style={styles.helperText}>
                {result.virustotal ? `${vtSummaryCount} engines` : "Optional"}
              </span>
            </div>

            {!result.virustotal_configured && (
              <div style={styles.noticeBox}>
                <Globe size={15} color="var(--color-blue)" />
                <div>
                  <p style={styles.noticeTitle}>VirusTotal is not configured</p>
                  <p style={styles.noticeText}>
                    Add an API key in Settings to enable VirusTotal lookups for URLs, domains, and IP addresses.
                  </p>
                </div>
                <button className="btn btn-ghost" style={styles.noticeAction} onClick={() => navigate("/settings")}>
                  Open Settings
                </button>
              </div>
            )}

            {result.virustotal_error && (
              <div style={{ ...styles.noticeBox, borderColor: "rgba(248,113,113,0.22)" }}>
                <AlertTriangle size={15} color="var(--color-red)" />
                <div>
                  <p style={styles.noticeTitle}>Threat intel lookup failed</p>
                  <p style={styles.noticeText}>{result.virustotal_error}</p>
                </div>
              </div>
            )}

            {result.virustotal ? (
              <>
                <div style={styles.vtGrid}>
                  <div style={styles.vtCard}>
                    <p style={styles.vtLabel}>Malicious</p>
                    <p style={{ ...styles.vtValue, color: "var(--color-red)" }}>
                      {result.virustotal.malicious}
                    </p>
                  </div>
                  <div style={styles.vtCard}>
                    <p style={styles.vtLabel}>Suspicious</p>
                    <p style={{ ...styles.vtValue, color: "var(--color-yellow)" }}>
                      {result.virustotal.suspicious}
                    </p>
                  </div>
                  <div style={styles.vtCard}>
                    <p style={styles.vtLabel}>Harmless</p>
                    <p style={{ ...styles.vtValue, color: "var(--color-green)" }}>
                      {result.virustotal.harmless}
                    </p>
                  </div>
                  <div style={styles.vtCard}>
                    <p style={styles.vtLabel}>Undetected</p>
                    <p style={styles.vtValue}>{result.virustotal.undetected}</p>
                  </div>
                </div>

                <button
                  className="btn btn-primary"
                  style={{ width: "100%", justifyContent: "center", marginTop: 12 }}
                  onClick={() => void open(result.virustotal!.permalink)}
                >
                  <ExternalLink size={14} />
                  Open VirusTotal Report
                </button>
              </>
            ) : (
              <p style={styles.emptyCopy}>
                {result.virustotal_configured
                  ? `No VirusTotal verdict was returned for this ${targetLabel.toLowerCase()} lookup.`
                  : "VirusTotal results will appear here once a key is connected."}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  page: {
    maxWidth: 1180,
    display: "flex",
    flexDirection: "column",
    gap: 16,
  },
  hero: {
    display: "flex",
    justifyContent: "space-between",
    gap: 16,
    alignItems: "flex-start",
    flexWrap: "wrap",
  },
  eyebrow: {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    fontSize: 11,
    color: "var(--text-secondary)",
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    marginBottom: 8,
  },
  title: {
    fontSize: 24,
    fontWeight: 700,
    letterSpacing: "-0.02em",
    marginBottom: 4,
  },
  subtitle: {
    color: "var(--text-secondary)",
    fontSize: 13,
    maxWidth: 700,
    lineHeight: 1.7,
  },
  heroBadge: {
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
    padding: "8px 12px",
    borderRadius: 999,
    background: "rgba(96,165,250,0.08)",
    border: "1px solid rgba(96,165,250,0.16)",
    color: "var(--color-blue)",
    fontSize: 12,
    fontWeight: 600,
    whiteSpace: "nowrap",
  },
  topGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
    gap: 16,
  },
  inputCard: {
    display: "flex",
    flexDirection: "column",
    gap: 14,
    background:
      "linear-gradient(160deg, rgba(96,165,250,0.08) 0%, rgba(96,165,250,0.02) 18%, var(--bg-card) 70%)",
  },
  historyCard: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
  sectionHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: 12,
    alignItems: "center",
    flexWrap: "wrap",
  },
  headerActions: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    flexWrap: "wrap",
    justifyContent: "flex-end",
  },
  cardHeading: {
    display: "flex",
    alignItems: "center",
    gap: 8,
  },
  cardLabel: {
    fontSize: 12,
    fontWeight: 700,
    color: "var(--text-secondary)",
    textTransform: "uppercase",
    letterSpacing: "0.06em",
  },
  helperText: {
    fontSize: 11,
    color: "var(--text-muted)",
  },
  clearHistoryButton: {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    fontSize: 11,
    padding: "6px 10px",
  },
  inputRow: {
    display: "flex",
    gap: 10,
    alignItems: "center",
  },
  exampleRow: {
    display: "flex",
    flexWrap: "wrap",
    gap: 8,
  },
  exampleButton: {
    fontSize: 11,
    padding: "5px 10px",
    maxWidth: "100%",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  infoStrip: {
    display: "flex",
    flexWrap: "wrap",
    gap: 10,
  },
  infoItem: {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    padding: "8px 10px",
    borderRadius: 10,
    background: "var(--bg-secondary)",
    border: "1px solid var(--border)",
    color: "var(--text-secondary)",
    fontSize: 12,
  },
  errorBox: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "10px 12px",
    borderRadius: 10,
    background: "rgba(248,113,113,0.08)",
    border: "1px solid rgba(248,113,113,0.22)",
    color: "var(--text-primary)",
    fontSize: 12,
  },
  historyList: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  historyItem: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12,
    padding: "10px 12px",
    borderRadius: 12,
    background: "var(--bg-secondary)",
    border: "1px solid var(--border)",
    cursor: "pointer",
    textAlign: "left",
    color: "inherit",
  },
  historyInput: {
    fontSize: 12,
    color: "var(--text-primary)",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    maxWidth: 260,
  },
  historyMeta: {
    fontSize: 11,
    color: "var(--text-muted)",
    marginTop: 2,
  },
  historyRight: {
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-end",
    gap: 2,
    flexShrink: 0,
  },
  historyScore: {
    fontSize: 14,
    fontWeight: 700,
  },
  historyDomain: {
    fontSize: 11,
    color: "var(--text-muted)",
    maxWidth: 120,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
  emptyCopy: {
    fontSize: 12,
    color: "var(--text-muted)",
    lineHeight: 1.7,
  },
  statGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: 12,
  },
  statCard: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
    minHeight: 96,
    justifyContent: "space-between",
  },
  statLabel: {
    fontSize: 10,
    fontWeight: 700,
    color: "var(--text-muted)",
    textTransform: "uppercase",
    letterSpacing: "0.08em",
  },
  statValueRow: {
    display: "flex",
    alignItems: "center",
    gap: 8,
  },
  statValue: {
    fontSize: 20,
    fontWeight: 700,
    letterSpacing: "-0.02em",
  },
  resultGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
    gap: 16,
  },
  primaryResultCard: {
    display: "flex",
    flexDirection: "column",
    gap: 16,
  },
  sideCard: {
    display: "flex",
    flexDirection: "column",
    gap: 14,
  },
  verdictBanner: {
    display: "flex",
    justifyContent: "space-between",
    gap: 12,
    alignItems: "center",
    padding: 14,
    borderRadius: 14,
    border: "1px solid",
  },
  verdictBannerLeft: {
    display: "flex",
    alignItems: "center",
    gap: 10,
  },
  bannerTitle: {
    fontSize: 16,
    fontWeight: 700,
    marginBottom: 2,
  },
  bannerCopy: {
    fontSize: 12,
    color: "var(--text-secondary)",
  },
  copyButton: {
    flexShrink: 0,
  },
  progressWrap: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  progressTrack: {
    width: "100%",
    height: 8,
    borderRadius: 999,
    background: "var(--bg-secondary)",
    overflow: "hidden",
    border: "1px solid var(--border)",
  },
  progressFill: {
    height: "100%",
    borderRadius: 999,
    transition: "width 0.24s ease",
  },
  progressMeta: {
    display: "flex",
    justifyContent: "space-between",
    fontSize: 11,
    color: "var(--text-muted)",
  },
  detailGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
    gap: 12,
  },
  detailCard: {
    padding: 12,
    borderRadius: 12,
    background: "var(--bg-secondary)",
    border: "1px solid var(--border)",
  },
  detailLabel: {
    fontSize: 10,
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    color: "var(--text-muted)",
    marginBottom: 6,
    fontWeight: 700,
  },
  detailValue: {
    fontSize: 14,
    fontWeight: 600,
    color: "var(--text-primary)",
    wordBreak: "break-word",
  },
  detailValueMono: {
    fontSize: 12,
    fontFamily: "var(--font-mono)",
    color: "var(--text-primary)",
    wordBreak: "break-all",
    lineHeight: 1.6,
  },
  detailMeta: {
    fontSize: 11,
    color: "var(--text-muted)",
    marginTop: 4,
  },
  sectionBlock: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
  },
  findingList: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  findingItem: {
    display: "flex",
    alignItems: "flex-start",
    gap: 8,
    padding: "10px 12px",
    borderRadius: 12,
    background: "var(--bg-secondary)",
    border: "1px solid var(--border)",
    color: "var(--text-secondary)",
    fontSize: 12,
    lineHeight: 1.6,
  },
  keywordWrap: {
    display: "flex",
    flexWrap: "wrap",
    gap: 8,
  },
  keywordChip: {
    display: "inline-flex",
    alignItems: "center",
    padding: "6px 10px",
    borderRadius: 999,
    background: "rgba(251,191,36,0.12)",
    border: "1px solid rgba(251,191,36,0.2)",
    color: "var(--color-yellow)",
    fontSize: 12,
    fontWeight: 600,
  },
  noticeBox: {
    display: "flex",
    gap: 10,
    alignItems: "flex-start",
    padding: 12,
    borderRadius: 12,
    background: "var(--bg-secondary)",
    border: "1px solid var(--border)",
  },
  noticeTitle: {
    fontSize: 12,
    fontWeight: 700,
    color: "var(--text-primary)",
    marginBottom: 3,
  },
  noticeText: {
    fontSize: 12,
    color: "var(--text-secondary)",
    lineHeight: 1.6,
  },
  noticeAction: {
    marginLeft: "auto",
    flexShrink: 0,
    alignSelf: "center",
  },
  vtGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
    gap: 10,
  },
  vtCard: {
    padding: 12,
    borderRadius: 12,
    background: "var(--bg-secondary)",
    border: "1px solid var(--border)",
  },
  vtLabel: {
    fontSize: 10,
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    color: "var(--text-muted)",
    fontWeight: 700,
    marginBottom: 6,
  },
  vtValue: {
    fontSize: 20,
    fontWeight: 700,
    color: "var(--text-primary)",
  },
  spinner: {
    animation: "spin 1s linear infinite",
  },
};
