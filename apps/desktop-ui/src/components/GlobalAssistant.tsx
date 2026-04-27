import { useEffect, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { AlertTriangle, MessageSquare, Send, Sparkles, Trash2, X } from "lucide-react";
import { askAi } from "@/lib/invoke";
import { useAssistantSignal } from "@/components/AssistantSignalContext";
import robotLogo from "@/assets/robot.png";

type Message = {
  role: "user" | "assistant";
  content: string;
};

type AssistantContext = {
  label: string;
  description: string;
  hint: string;
  prompts: string[];
};

const DEFAULT_CONTEXT: AssistantContext = {
  label: "Threat Guard",
  description: "The user is working in the main Threat Guard interface.",
  hint: "Need a hand?",
  prompts: [
    "Is my PC safe right now?",
    "What should I review first?",
    "Summarize any suspicious activity.",
  ],
};

function getAssistantContext(pathname: string): AssistantContext {
  if (pathname.startsWith("/processes/")) {
    return {
      label: "Process Details",
      description: "The user is reviewing a specific process and likely needs help understanding its behavior or risk.",
      hint: "Questions about this process?",
      prompts: [
        "What should I check first on this process?",
        "How do I tell if this process is risky?",
        "What details matter most on this page?",
      ],
    };
  }

  if (pathname.startsWith("/dashboard")) {
    return {
      label: "Dashboard",
      description: "The user is looking at the system health, alerts, startup changes, and suspicious process summaries.",
      hint: "Want a quick health summary?",
      prompts: [
        "Give me a quick summary of my system health.",
        "What looks most risky right now?",
        "What should I investigate first from the dashboard?",
      ],
    };
  }

  if (pathname.startsWith("/processes")) {
    return {
      label: "Processes",
      description: "The user is viewing the monitored process list and may want help prioritizing suspicious processes.",
      hint: "Need help sorting the noisy stuff?",
      prompts: [
        "Which processes deserve attention first?",
        "What signs suggest a process is suspicious?",
        "How should I prioritize this process list?",
      ],
    };
  }

  if (pathname.startsWith("/alerts")) {
    return {
      label: "Alerts",
      description: "The user is reviewing open alerts and likely wants help understanding urgency or next steps.",
      hint: "Need help with these alerts?",
      prompts: [
        "Summarize my open alerts.",
        "Which alert should I handle first?",
        "What action should I take on high-risk alerts?",
      ],
    };
  }

  if (pathname.startsWith("/startup")) {
    return {
      label: "Startup Entries",
      description: "The user is reviewing startup items and may want help spotting persistence risks.",
      hint: "Questions about startup items?",
      prompts: [
        "What makes a startup entry suspicious?",
        "How should I review new startup entries?",
        "Which startup items usually deserve more scrutiny?",
      ],
    };
  }

  if (pathname.startsWith("/events")) {
    return {
      label: "Event Log",
      description: "The user is looking through the event timeline for security and activity changes.",
      hint: "Want help reading the timeline?",
      prompts: [
        "Summarize the recent event activity.",
        "What patterns should I watch for in these events?",
        "Which recent events look the most important?",
      ],
    };
  }

  if (pathname.startsWith("/phishing-detector")) {
    return {
      label: "Phishing Detector",
      description: "The user is analyzing suspicious email content and may want help understanding phishing indicators.",
      hint: "Need a second opinion on phishing signs?",
      prompts: [
        "What signs usually make an email look malicious?",
        "How should I interpret a suspicious phishing result?",
        "What details matter most when reviewing a message?",
      ],
    };
  }

  if (pathname.startsWith("/malicious-link-detector")) {
    return {
      label: "Malicious Link Detector",
      description: "The user is scanning a URL, domain, or IP address and may want help interpreting reputation and heuristic signals.",
      hint: "Need help reading this scan?",
      prompts: [
        "How should I interpret a suspicious link result?",
        "What does VirusTotal tell me here?",
        "What should I do before opening a suspicious link?",
      ],
    };
  }

  if (pathname.startsWith("/password-manager")) {
    return {
      label: "Password Manager",
      description: "The user is reviewing passwords or stored credentials and may want help with safe password practices.",
      hint: "Need password guidance?",
      prompts: [
        "What makes a password strong?",
        "How do I know when a password needs to be changed?",
        "What password habits lower risk the most?",
      ],
    };
  }

  if (pathname.startsWith("/settings")) {
    return {
      label: "Settings",
      description: "The user is adjusting app configuration and may want help understanding setup choices.",
      hint: "Need help with setup?",
      prompts: [
        "Which settings matter most for protection?",
        "What should I configure first?",
        "How do the AI and VirusTotal settings help?",
      ],
    };
  }

  return DEFAULT_CONTEXT;
}

function buildContextualPrompt(
  question: string,
  context: AssistantContext,
  signal?: { title: string; message: string } | null,
): string {
  return `The user is currently on the "${context.label}" page in Threat Guard. ${context.description}
${signal ? `\nCurrent assistant alert: ${signal.title}. ${signal.message}` : ""}

User question: ${question}`;
}

export default function GlobalAssistant() {
  const location = useLocation();
  const { signal } = useAssistantSignal();
  const context = getAssistantContext(location.pathname);
  const activeSignal =
    signal && location.pathname.startsWith(signal.path) ? signal : null;
  const [isOpen, setIsOpen] = useState(false);
  const [showHint, setShowHint] = useState(true);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const promptOptions = Array.from(
    new Set([...(activeSignal?.prompts ?? []), ...context.prompts]),
  ).slice(0, 4);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading, isOpen]);

  useEffect(() => {
    if (isOpen) {
      setShowHint(false);
      return;
    }

    const timer = window.setTimeout(
      () => setShowHint(false),
      activeSignal ? 14000 : 9000,
    );
    return () => window.clearTimeout(timer);
  }, [isOpen, activeSignal]);

  useEffect(() => {
    if (activeSignal && !isOpen) {
      setShowHint(true);
    }
  }, [activeSignal, isOpen]);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isOpen]);

  const sendMessage = async (text: string) => {
    const question = text.trim();
    if (!question || loading) {
      return;
    }

    const history = messages
      .slice(-6)
      .map((message) => ({ role: message.role, content: message.content }));

    setMessages((current) => [...current, { role: "user", content: question }]);
    setInput("");
    setLoading(true);

    try {
      const answer = await askAi(buildContextualPrompt(question, context, activeSignal), history);
      setMessages((current) => [...current, { role: "assistant", content: answer }]);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setMessages((current) => [
        ...current,
        { role: "assistant", content: `Error: ${errorMessage}` },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void sendMessage(input);
    }
  };

  const handleReset = () => {
    setMessages([]);
    setInput("");
  };

  return (
    <>
      {isOpen && <div style={styles.scrim} onClick={() => setIsOpen(false)} />}

      <div
        style={{
          ...styles.panel,
          opacity: isOpen ? 1 : 0,
          transform: isOpen ? "translateY(0) scale(1)" : "translateY(18px) scale(0.96)",
          pointerEvents: isOpen ? "auto" : "none",
        }}
        className="card"
      >
        <div style={styles.panelHeader}>
          <div style={styles.headerLeft}>
            <div style={styles.robotWrap}>
              <img src={robotLogo} alt="Threat Guard robot" style={styles.robotImage} />
            </div>
            <div>
              <p style={styles.headerTitle}>Threat Guard Assistant</p>
              <p style={styles.headerSubtitle}>
                {activeSignal
                  ? activeSignal.message
                  : `Ready to help with ${context.label.toLowerCase()}`}
              </p>
            </div>
          </div>

          <div style={styles.headerActions}>
            <button
              className="btn btn-ghost"
              style={styles.iconButton}
              onClick={handleReset}
              disabled={messages.length === 0 && !input.trim()}
              title="Start a new chat"
            >
              <Trash2 size={14} />
            </button>
            <button
              className="btn btn-ghost"
              style={styles.iconButton}
              onClick={() => setIsOpen(false)}
              title="Close assistant"
            >
              <X size={14} />
            </button>
          </div>
        </div>

        <div style={styles.chatArea}>
          {messages.length === 0 ? (
            <div style={styles.emptyState}>
              {activeSignal && (
                <div style={styles.signalCard}>
                  <div style={styles.signalBadge}>
                    <AlertTriangle size={14} color="var(--color-orange)" />
                    <span>Threat Guard Alert</span>
                  </div>
                  <p style={styles.signalTitle}>{activeSignal.title}</p>
                  <p style={styles.signalText}>{activeSignal.message}</p>
                </div>
              )}
              <div style={styles.emptyBadge}>
                <Sparkles size={14} color="var(--color-blue)" />
                <span>{context.label}</span>
              </div>
              <p style={styles.emptyTitle}>Ask anything about this part of Threat Guard</p>
              <p style={styles.emptyHint}>
                I can help explain what you are seeing, what looks risky, and what to do next.
              </p>
              <div style={styles.promptList}>
                {promptOptions.map((prompt) => (
                  <button
                    key={prompt}
                    className="btn btn-ghost"
                    style={styles.promptButton}
                    onClick={() => void sendMessage(prompt)}
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div style={styles.messageList}>
              {messages.map((message, index) => (
                <div
                  key={`${message.role}-${index}`}
                  style={{
                    ...styles.messageRow,
                    justifyContent: message.role === "user" ? "flex-end" : "flex-start",
                  }}
                >
                  {message.role === "assistant" && (
                    <div style={styles.messageAvatar}>
                      <img src={robotLogo} alt="" style={styles.messageAvatarImage} />
                    </div>
                  )}

                  <div
                    style={{
                      ...styles.messageBubble,
                      ...(message.role === "user"
                        ? styles.userBubble
                        : styles.assistantBubble),
                    }}
                  >
                    {message.content}
                  </div>
                </div>
              ))}

              {loading && (
                <div style={{ ...styles.messageRow, justifyContent: "flex-start" }}>
                  <div style={styles.messageAvatar}>
                    <img src={robotLogo} alt="" style={styles.messageAvatarImage} />
                  </div>
                  <div
                    style={{
                      ...styles.messageBubble,
                      ...styles.assistantBubble,
                      ...styles.loadingBubble,
                    }}
                  >
                    Reviewing your Threat Guard context...
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        <div style={styles.inputArea}>
          <textarea
            className="input"
            style={styles.input}
            placeholder={`Ask about ${context.label.toLowerCase()}, alerts, risks, or next steps...`}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
          />
          <button
            className="btn btn-primary"
            style={styles.sendButton}
            onClick={() => void sendMessage(input)}
            disabled={!input.trim() || loading}
            title="Send"
          >
            <Send size={15} />
          </button>
        </div>
      </div>

      {showHint && !isOpen && (
        <button
          style={{
            ...styles.hintBubble,
            ...(activeSignal ? styles.hintBubbleAlert : {}),
          }}
          onClick={() => setIsOpen(true)}
        >
          {activeSignal ? (
            <AlertTriangle size={13} color="var(--color-orange)" />
          ) : (
            <Sparkles size={13} color="var(--color-blue)" />
          )}
          <span>{activeSignal ? activeSignal.message : context.hint}</span>
        </button>
      )}

      <button
        style={styles.launcher}
        onClick={() => {
          setIsOpen((current) => !current);
          setShowHint(false);
        }}
        title="Open Threat Guard Assistant"
      >
        <img src={robotLogo} alt="Threat Guard Assistant" style={styles.launcherImage} />
        <div
          style={{
            ...styles.launcherRing,
            ...(activeSignal ? styles.launcherRingAlert : {}),
          }}
        >
          {activeSignal ? (
            activeSignal.badgeCount ? (
              <span style={styles.launcherBadgeCount}>
                {Math.min(activeSignal.badgeCount, 9)}
              </span>
            ) : (
              <AlertTriangle size={14} color="white" />
            )
          ) : (
            <MessageSquare size={15} color="white" />
          )}
        </div>
      </button>
    </>
  );
}

const styles: Record<string, React.CSSProperties> = {
  scrim: {
    position: "fixed",
    inset: 0,
    background: "rgba(15,23,42,0.14)",
    zIndex: 29,
  },
  panel: {
    position: "fixed",
    right: 16,
    bottom: 96,
    width: "min(400px, calc(100vw - 32px))",
    height: "min(560px, calc(100vh - 128px))",
    zIndex: 30,
    display: "flex",
    flexDirection: "column",
    padding: 0,
    borderRadius: 22,
    boxShadow: "0 26px 70px rgba(15,23,42,0.24)",
    overflow: "hidden",
    transformOrigin: "bottom right",
    transition: "opacity 0.18s ease, transform 0.18s ease",
    background:
      "linear-gradient(180deg, rgba(96,165,250,0.08) 0%, rgba(255,255,255,0) 18%), var(--bg-card)",
  },
  panelHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12,
    padding: "16px 16px 12px",
    borderBottom: "1px solid var(--border)",
  },
  headerLeft: {
    display: "flex",
    alignItems: "center",
    gap: 12,
    minWidth: 0,
  },
  robotWrap: {
    width: 42,
    height: 42,
    borderRadius: 14,
    background: "linear-gradient(180deg, rgba(96,165,250,0.18), rgba(96,165,250,0.08))",
    border: "1px solid rgba(96,165,250,0.26)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },
  robotImage: {
    width: 28,
    height: 28,
    objectFit: "contain",
  },
  headerTitle: {
    fontSize: 14,
    fontWeight: 700,
    color: "var(--text-primary)",
    marginBottom: 2,
  },
  headerSubtitle: {
    fontSize: 11,
    color: "var(--text-muted)",
    lineHeight: 1.5,
  },
  headerActions: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    flexShrink: 0,
  },
  iconButton: {
    width: 34,
    height: 34,
    padding: 0,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
  },
  chatArea: {
    flex: 1,
    minHeight: 0,
    overflow: "auto",
    padding: 14,
  },
  emptyState: {
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
    justifyContent: "center",
    gap: 12,
    minHeight: "100%",
    padding: 4,
  },
  signalCard: {
    width: "100%",
    padding: 14,
    borderRadius: 16,
    background: "rgba(251,146,60,0.08)",
    border: "1px solid rgba(251,146,60,0.22)",
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  signalBadge: {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    padding: "6px 10px",
    borderRadius: 999,
    background: "rgba(251,146,60,0.12)",
    color: "var(--color-orange)",
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: "0.05em",
    textTransform: "uppercase",
  },
  signalTitle: {
    fontSize: 15,
    fontWeight: 700,
    color: "var(--text-primary)",
  },
  signalText: {
    fontSize: 13,
    lineHeight: 1.65,
    color: "var(--text-secondary)",
  },
  emptyBadge: {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    padding: "7px 10px",
    borderRadius: 999,
    background: "rgba(96,165,250,0.08)",
    border: "1px solid rgba(96,165,250,0.18)",
    fontSize: 11,
    fontWeight: 700,
    color: "var(--color-blue)",
    textTransform: "uppercase",
    letterSpacing: "0.06em",
  },
  emptyTitle: {
    fontSize: 18,
    fontWeight: 700,
    color: "var(--text-primary)",
    lineHeight: 1.3,
  },
  emptyHint: {
    fontSize: 13,
    color: "var(--text-secondary)",
    lineHeight: 1.7,
    maxWidth: 320,
  },
  promptList: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
    width: "100%",
    marginTop: 4,
  },
  promptButton: {
    justifyContent: "flex-start",
    fontSize: 12,
    textAlign: "left",
    padding: "10px 12px",
    borderRadius: 12,
  },
  messageList: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
  messageRow: {
    display: "flex",
    alignItems: "flex-end",
    gap: 8,
  },
  messageAvatar: {
    width: 28,
    height: 28,
    borderRadius: 10,
    background: "rgba(96,165,250,0.08)",
    border: "1px solid rgba(96,165,250,0.18)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },
  messageAvatarImage: {
    width: 18,
    height: 18,
    objectFit: "contain",
  },
  messageBubble: {
    maxWidth: "82%",
    padding: "10px 13px",
    fontSize: 13,
    lineHeight: 1.65,
    whiteSpace: "pre-wrap",
    wordBreak: "break-word",
    border: "1px solid transparent",
  },
  userBubble: {
    background: "linear-gradient(180deg, #60A5FA 0%, #3B82F6 100%)",
    color: "white",
    borderRadius: "16px 16px 4px 16px",
  },
  assistantBubble: {
    background: "var(--bg-secondary)",
    color: "var(--text-primary)",
    borderColor: "var(--border)",
    borderRadius: "4px 16px 16px 16px",
  },
  loadingBubble: {
    color: "var(--text-muted)",
    fontStyle: "italic",
  },
  inputArea: {
    display: "flex",
    gap: 10,
    alignItems: "flex-end",
    padding: 14,
    borderTop: "1px solid var(--border)",
    background: "rgba(248,250,252,0.52)",
  },
  input: {
    resize: "none",
    minHeight: 54,
    maxHeight: 120,
    lineHeight: 1.55,
    paddingTop: 12,
  },
  sendButton: {
    height: 54,
    padding: "0 18px",
    flexShrink: 0,
  },
  hintBubble: {
    position: "fixed",
    right: 88,
    bottom: 30,
    zIndex: 29,
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
    padding: "10px 14px",
    borderRadius: 999,
    border: "1px solid rgba(96,165,250,0.18)",
    background: "rgba(255,255,255,0.96)",
    color: "var(--text-primary)",
    boxShadow: "0 14px 36px rgba(15,23,42,0.14)",
    fontSize: 12,
    fontWeight: 600,
    cursor: "pointer",
    maxWidth: "min(260px, calc(100vw - 112px))",
    textAlign: "left",
  },
  hintBubbleAlert: {
    border: "1px solid rgba(251,146,60,0.22)",
    background: "rgba(255,247,237,0.98)",
    boxShadow: "0 14px 36px rgba(249,115,22,0.16)",
  },
  launcher: {
    position: "fixed",
    right: 16,
    bottom: 16,
    width: 64,
    height: 64,
    borderRadius: "50%",
    border: "1px solid rgba(96,165,250,0.28)",
    background: "linear-gradient(180deg, #F8FBFF 0%, #DCEEFF 100%)",
    boxShadow: "0 18px 40px rgba(59,130,246,0.24)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    cursor: "pointer",
    zIndex: 31,
    padding: 0,
  },
  launcherImage: {
    width: 34,
    height: 34,
    objectFit: "contain",
  },
  launcherRing: {
    position: "absolute",
    right: -2,
    bottom: -2,
    width: 28,
    height: 28,
    borderRadius: "50%",
    background: "linear-gradient(180deg, #3B82F6 0%, #2563EB 100%)",
    border: "2px solid white",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    boxShadow: "0 10px 20px rgba(37,99,235,0.24)",
  },
  launcherRingAlert: {
    background: "linear-gradient(180deg, #FB923C 0%, #F97316 100%)",
    boxShadow: "0 10px 20px rgba(249,115,22,0.26)",
  },
  launcherBadgeCount: {
    fontSize: 11,
    fontWeight: 800,
    color: "white",
    lineHeight: 1,
  },
};
