import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Play,
  RefreshCw,
  Rocket,
  Search,
  Shield,
  Square,
  User,
  type LucideIcon,
} from "lucide-react";
import { askAi, listActivityEventsPaged } from "@/lib/invoke";
import type { ActivityEvent } from "@/types";

type EventFilter =
  | "all"
  | "process_created"
  | "process_terminated"
  | "alert"
  | "startup"
  | "user_action";
type SevFilter = "all" | "high" | "medium" | "low" | "info";

const PAGE_SIZE = 50;

const EVENT_ICONS: Record<string, LucideIcon> = {
  process_created: Play,
  process_terminated: Square,
  alert: AlertTriangle,
  startup: Rocket,
  user_action: User,
};

const SEV_COLORS: Record<string, string> = {
  high: "var(--color-red)",
  medium: "var(--color-orange)",
  low: "var(--color-yellow)",
  info: "var(--color-blue)",
};

const TYPE_LABELS: Record<string, string> = {
  process_created: "Process Started",
  process_terminated: "Process Ended",
  alert: "Alert",
  startup: "Startup",
  user_action: "User Action",
};

export default function EventsPage() {
  const navigate = useNavigate();
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [typeFilter, setTypeFilter] = useState<EventFilter>("all");
  const [sevFilter, setSevFilter] = useState<SevFilter>("all");
  const [search, setSearch] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<ActivityEvent | null>(null);
  const [aiQuestion, setAiQuestion] = useState("");
  const [aiAnswer, setAiAnswer] = useState("");
  const [aiLoading, setAiLoading] = useState(false);

  const fetchPage = useCallback(async (nextPage: number) => {
    setLoading(true);
    try {
      const result = await listActivityEventsPaged(PAGE_SIZE, nextPage * PAGE_SIZE);
      setEvents(result.events);
      setTotal(result.total);
    } catch (err) {
      console.error("Failed to fetch events:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchPage(page);
  }, [fetchPage, page]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      void fetchPage(page);
    }, 30000);

    return () => window.clearInterval(interval);
  }, [fetchPage, page]);

  const filtered = events.filter((event) => {
    if (typeFilter !== "all" && event.event_type !== typeFilter) return false;
    if (sevFilter !== "all" && event.severity !== sevFilter) return false;
    if (search) {
      const query = search.toLowerCase();
      if (
        !event.title.toLowerCase().includes(query) &&
        !event.description.toLowerCase().includes(query)
      ) {
        return false;
      }
    }
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const handleEventClick = (event: ActivityEvent) => {
    if (event.event_type === "alert" && event.related_id) {
      navigate("/alerts");
    } else if (
      (event.event_type === "process_created" ||
        event.event_type === "process_terminated") &&
      event.related_id
    ) {
      navigate(`/processes/${event.related_id}`);
    } else if (event.event_type === "startup" && event.related_id) {
      navigate("/startup");
    }
  };

  const handleAskEventAi = async (question?: string) => {
    const prompt = (question || aiQuestion).trim();
    if (!prompt || aiLoading) return;

    setAiLoading(true);

    const context = selectedEvent
      ? `Event details:\nTitle: ${selectedEvent.title}\nType: ${
          TYPE_LABELS[selectedEvent.event_type] || selectedEvent.event_type
        }\nSeverity: ${selectedEvent.severity}\nTime: ${
          selectedEvent.timestamp
        }\nDescription: ${selectedEvent.description}`
      : `Recent events on the page include ${filtered.length} items.`;

    try {
      const answer = await askAi(`${context}\n\nQuestion: ${prompt}`);
      setAiAnswer(answer);
      setAiQuestion("");
    } catch (err) {
      setAiAnswer(`Error: ${String(err)}`);
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 16,
        }}
      >
        <div>
          <h1 style={styles.pageTitle}>Event Log</h1>
          <p style={styles.subtitle}>
            Security timeline - processes, alerts, startup changes, and user actions
          </p>
        </div>
        <button
          className="btn btn-ghost"
          style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}
          onClick={() => void fetchPage(page)}
          disabled={loading}
        >
          <RefreshCw
            size={13}
            style={loading ? { animation: "spin 1s linear infinite" } : undefined}
          />
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      <div style={styles.toolbar}>
        <div style={styles.searchWrap}>
          <Search size={13} style={styles.searchIcon} />
          <input
            className="input"
            style={{ paddingLeft: 30 }}
            placeholder="Search events..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>

        <select
          className="input"
          style={{ width: 170 }}
          value={typeFilter}
          onChange={(event) => {
            setTypeFilter(event.target.value as EventFilter);
            setPage(0);
          }}
        >
          <option value="all">All types</option>
          <option value="alert">Alerts</option>
          <option value="process_created">Process Started</option>
          <option value="process_terminated">Process Ended</option>
          <option value="startup">Startup</option>
          <option value="user_action">User Actions</option>
        </select>

        <select
          className="input"
          style={{ width: 140 }}
          value={sevFilter}
          onChange={(event) => {
            setSevFilter(event.target.value as SevFilter);
            setPage(0);
          }}
        >
          <option value="all">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        <span style={styles.count}>
          {filtered.length} / {total} events
        </span>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {filtered.length === 0 ? (
          <p style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
            {loading ? "Loading events..." : "No events match your filters"}
          </p>
        ) : (
          <div style={styles.timeline}>
            {filtered.map((event, index) => {
              const Icon: LucideIcon = EVENT_ICONS[event.event_type] ?? Shield;
              const color = SEV_COLORS[event.severity] ?? "var(--color-blue)";
              const isClickable = !!event.related_id && event.event_type !== "user_action";
              const isSelected = selectedEvent?.id === event.id;

              return (
                <div
                  key={`${event.id}-${index}`}
                  style={{
                    ...styles.eventRow,
                    cursor: isClickable ? "pointer" : "default",
                    background: isSelected ? "rgba(96,165,250,0.08)" : undefined,
                    borderLeft: isSelected
                      ? "3px solid rgba(96,165,250,0.9)"
                      : undefined,
                  }}
                  onClick={isClickable ? () => handleEventClick(event) : undefined}
                >
                  <div style={styles.iconCol}>
                    <div
                      style={{
                        ...styles.iconWrap,
                        background: `${color}18`,
                        border: `1px solid ${color}40`,
                      }}
                    >
                      <Icon size={13} color={color} />
                    </div>
                    {index < filtered.length - 1 && <div style={styles.connector} />}
                  </div>

                  <div style={styles.content}>
                    <div style={styles.contentRow}>
                      <span className={`badge badge-${event.severity}`} style={{ fontSize: 10 }}>
                        {event.severity}
                      </span>
                      <span style={styles.typeLabel}>
                        {TYPE_LABELS[event.event_type] ?? event.event_type}
                      </span>
                      <span style={styles.time}>
                        {formatDistanceToNow(new Date(event.timestamp), {
                          addSuffix: true,
                        })}
                      </span>
                    </div>

                    <div style={styles.title}>{event.title}</div>
                    {event.description && (
                      <div style={styles.desc} className="mono">
                        {event.description}
                      </div>
                    )}

                    <div style={styles.rowActions}>
                      <button
                        className="btn btn-ghost"
                        style={styles.askEventButton}
                        onClick={(clickEvent) => {
                          clickEvent.stopPropagation();
                          setSelectedEvent(event);
                          setAiAnswer("");
                        }}
                      >
                        Ask AI about this event
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="card" style={{ marginTop: 20, padding: 20 }}>
        <div style={styles.aiHeader}>
          <div>
            <h2 style={styles.aiTitle}>Ask AI about this event</h2>
            <p style={styles.aiSubtitle}>
              Select an event above, then ask a question to get a quick explanation.
            </p>
          </div>
          {selectedEvent ? <span style={styles.aiBadge}>Selected</span> : null}
        </div>

        <div style={styles.aiContext}>
          {selectedEvent ? (
            <div style={styles.aiEventCard}>
              <div style={styles.aiEventTitle}>{selectedEvent.title}</div>
              <div style={styles.aiEventMeta}>
                {TYPE_LABELS[selectedEvent.event_type] || selectedEvent.event_type} ·{" "}
                {selectedEvent.severity}
              </div>
              {selectedEvent.description ? (
                <div style={styles.aiEventText}>{selectedEvent.description}</div>
              ) : null}
            </div>
          ) : (
            <p style={styles.aiHint}>
              Click "Ask AI about this event" on any event card to set context here.
            </p>
          )}
        </div>

        <div style={styles.aiInputRow}>
          <input
            className="input"
            style={{ flex: 1, minWidth: 0 }}
            placeholder={
              selectedEvent
                ? "Ask a question about the selected event..."
                : "Ask about recent events..."
            }
            value={aiQuestion}
            onChange={(event) => setAiQuestion(event.target.value)}
            onKeyDown={(event) =>
              event.key === "Enter" && !event.shiftKey && void handleAskEventAi()
            }
            disabled={aiLoading}
          />
          <button
            className="btn btn-primary"
            style={{ minWidth: 120 }}
            disabled={aiLoading || !aiQuestion.trim()}
            onClick={() => void handleAskEventAi()}
          >
            {aiLoading ? "Thinking..." : "Ask AI"}
          </button>
        </div>

        {aiAnswer ? (
          <div style={styles.aiAnswerCard}>
            <div style={styles.aiAnswerLabel}>AI Response</div>
            <div style={styles.aiAnswerText}>{aiAnswer}</div>
          </div>
        ) : null}
      </div>

      {totalPages > 1 && (
        <div style={styles.pagination}>
          <button
            className="btn btn-ghost"
            style={{ padding: "4px 8px" }}
            disabled={page === 0 || loading}
            onClick={() => setPage((currentPage) => currentPage - 1)}
          >
            <ChevronLeft size={14} />
          </button>
          <span style={styles.pageInfo}>
            Page {page + 1} of {totalPages}
          </span>
          <button
            className="btn btn-ghost"
            style={{ padding: "4px 8px" }}
            disabled={page >= totalPages - 1 || loading}
            onClick={() => setPage((currentPage) => currentPage + 1)}
          >
            <ChevronRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  pageTitle: { fontSize: 22, fontWeight: 700, marginBottom: 2 },
  subtitle: { fontSize: 12, color: "var(--text-muted)", marginTop: 0 },
  toolbar: { display: "flex", gap: 10, alignItems: "center", marginBottom: 14 },
  searchWrap: { flex: 1, position: "relative" },
  searchIcon: {
    position: "absolute",
    left: 9,
    top: "50%",
    transform: "translateY(-50%)",
    color: "var(--text-muted)",
    pointerEvents: "none",
  },
  count: { fontSize: 12, color: "var(--text-muted)", whiteSpace: "nowrap" },
  timeline: { display: "flex", flexDirection: "column" },
  eventRow: {
    display: "flex",
    gap: 0,
    padding: "0 14px",
    borderBottom: "1px solid var(--border)",
    transition: "background 0.1s",
  },
  iconCol: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    paddingTop: 12,
    paddingRight: 14,
    flexShrink: 0,
    width: 36,
  },
  iconWrap: {
    width: 28,
    height: 28,
    borderRadius: "50%",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },
  connector: {
    flex: 1,
    width: 1,
    background: "var(--border)",
    minHeight: 8,
    marginTop: 4,
  },
  content: { flex: 1, paddingTop: 10, paddingBottom: 10 },
  contentRow: { display: "flex", alignItems: "center", gap: 8, marginBottom: 4 },
  typeLabel: { fontSize: 11, color: "var(--text-muted)", fontWeight: 500 },
  time: { fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" },
  title: {
    fontSize: 13,
    fontWeight: 600,
    color: "var(--text-primary)",
    marginBottom: 2,
  },
  desc: {
    fontSize: 11,
    color: "var(--text-muted)",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
    maxWidth: "100%",
  },
  rowActions: { marginTop: 10 },
  askEventButton: {
    fontSize: 11,
    padding: "6px 10px",
    borderRadius: 8,
    border: "1px solid rgba(255,255,255,0.08)",
    color: "var(--text-muted)",
  },
  aiHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 16,
    marginBottom: 14,
  },
  aiTitle: { fontSize: 16, fontWeight: 700, margin: 0 },
  aiSubtitle: { fontSize: 12, color: "var(--text-muted)", margin: 0 },
  aiBadge: {
    padding: "6px 10px",
    borderRadius: 999,
    fontSize: 11,
    color: "var(--color-blue)",
    background: "rgba(96,165,250,0.12)",
    border: "1px solid rgba(96,165,250,0.2)",
  },
  aiContext: { marginBottom: 14 },
  aiEventCard: {
    padding: 14,
    borderRadius: 12,
    border: "1px solid rgba(255,255,255,0.08)",
    background: "rgba(255,255,255,0.03)",
  },
  aiEventTitle: { fontSize: 13, fontWeight: 600, marginBottom: 4 },
  aiEventMeta: { fontSize: 11, color: "var(--text-muted)", marginBottom: 8 },
  aiEventText: { fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6 },
  aiHint: { fontSize: 12, color: "var(--text-muted)" },
  aiInputRow: {
    display: "flex",
    gap: 10,
    alignItems: "center",
    flexWrap: "wrap",
  },
  aiAnswerCard: {
    marginTop: 16,
    padding: 14,
    borderRadius: 12,
    background: "rgba(255,255,255,0.04)",
    border: "1px solid rgba(255,255,255,0.08)",
  },
  aiAnswerLabel: { fontSize: 11, color: "var(--text-muted)", marginBottom: 6 },
  aiAnswerText: {
    fontSize: 13,
    lineHeight: 1.7,
    color: "var(--text-primary)",
    whiteSpace: "pre-wrap",
  },
  pagination: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 12,
    marginTop: 12,
  },
  pageInfo: { fontSize: 12, color: "var(--text-muted)" },
};
