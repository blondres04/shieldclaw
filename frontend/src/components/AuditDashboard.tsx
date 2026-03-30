import { useCallback, useEffect, useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import type { PullRequest } from "../types/Audit";
import TelemetryChart from "./TelemetryChart";

const OWASP_CATEGORIES = [
  "OWASP_A01 - Broken Access Control",
  "Dependency Hijack",
  "SQL Injection",
] as const;

const API_BASE = "http://localhost:8080/api/v1/audit";

function authHeaders(): HeadersInit {
  return { Authorization: `Bearer ${localStorage.getItem("token")}` };
}

interface AuditDashboardProps {
  onUnauthorized: () => void;
}

export default function AuditDashboard({ onUnauthorized }: AuditDashboardProps) {
  const [pr, setPr] = useState<PullRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>(OWASP_CATEGORIES[0]);
  const [submitting, setSubmitting] = useState(false);

  const handleAuthError = useCallback(
    (status: number) => {
      if (status === 401 || status === 403) {
        localStorage.removeItem("token");
        onUnauthorized();
      }
    },
    [onUnauthorized],
  );

  const fetchPending = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/pending`, {
        headers: authHeaders(),
      });
      if (res.status === 401 || res.status === 403) {
        handleAuthError(res.status);
        return;
      }
      if (res.status === 204) {
        setPr(null);
      } else if (res.ok) {
        setPr(await res.json());
      } else {
        setError(`Failed to fetch: ${res.status}`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Network error");
    } finally {
      setLoading(false);
    }
  }, [handleAuthError]);

  useEffect(() => {
    fetchPending();
  }, [fetchPending]);

  const handleEvaluate = useCallback(
    async (isApproved: boolean) => {
      if (!pr) return;
      setSubmitting(true);
      try {
        const res = await fetch(`${API_BASE}/${pr.prId}/evaluate`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...authHeaders(),
          },
          body: JSON.stringify({
            selectedThreatCategory: selectedCategory,
            isApproved,
          }),
        });
        if (res.status === 401 || res.status === 403) {
          handleAuthError(res.status);
          return;
        }
        if (!res.ok) throw new Error(`Evaluate failed: ${res.status}`);
        await fetchPending();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Submit error");
      } finally {
        setSubmitting(false);
      }
    },
    [pr, selectedCategory, handleAuthError, fetchPending],
  );

  if (loading) {
    return (
      <div style={styles.center}>
        <p style={styles.muted}>Loading pending audit…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={styles.center}>
        <p style={styles.error} role="alert">{error}</p>
        <button
          style={styles.retryBtn}
          onClick={fetchPending}
          aria-label="Retry loading pending audit"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!pr) {
    return (
      <div style={styles.emptyState}>
        <p style={styles.muted}>No pending audits. You're all caught up.</p>
        <TelemetryChart onUnauthorized={onUnauthorized} />
      </div>
    );
  }

  return (
    <div style={styles.wrapper}>
      <header style={styles.header}>
        <h1 style={styles.title}>DevSecOps Audit Dashboard</h1>
        <span style={styles.badge}>PR {pr.prId}</span>
      </header>

      <section style={styles.diffContainer}>
        <ReactDiffViewer
          oldValue={pr.originalSnippet}
          newValue={pr.poisonedSnippet}
          splitView
          useDarkTheme
          leftTitle="Original Snippet"
          rightTitle="Poisoned Snippet"
        />
      </section>

      <section style={styles.actionPanel} aria-label="Audit action panel">
        <h2 style={styles.actionTitle}>Audit Action Panel</h2>

        <div style={styles.formRow}>
          <label htmlFor="owasp-category" style={styles.label}>
            OWASP Category
          </label>
          <select
            id="owasp-category"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            style={styles.select}
            aria-label="Select OWASP threat category"
          >
            {OWASP_CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>

        <div style={styles.buttonRow} role="group" aria-label="Audit decision">
          <button
            disabled={submitting}
            onClick={() => handleEvaluate(true)}
            style={styles.approveBtn}
            aria-label="Approve pull request as safe"
          >
            {submitting ? "Submitting…" : "Approve (No Threat)"}
          </button>
          <button
            disabled={submitting}
            onClick={() => handleEvaluate(false)}
            style={styles.rejectBtn}
            aria-label="Reject pull request as vulnerable"
          >
            {submitting ? "Submitting…" : "Reject (Vulnerability Found)"}
          </button>
        </div>
      </section>

      <TelemetryChart onUnauthorized={onUnauthorized} />
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    maxWidth: 1200,
    margin: "0 auto",
    padding: "0 24px 32px",
  },
  center: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "60vh",
    gap: 16,
  },
  emptyState: {
    maxWidth: 1200,
    margin: "0 auto",
    padding: "64px 24px 32px",
    textAlign: "center" as const,
  },
  muted: {
    color: "#8b8fa3",
    fontSize: 18,
  },
  error: {
    color: "#e74c3c",
    fontSize: 18,
  },
  retryBtn: {
    padding: "8px 20px",
    background: "#6c5ce7",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    cursor: "pointer",
    fontSize: 14,
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 24,
  },
  title: {
    fontSize: 28,
    fontWeight: 700,
    color: "#e1e2e8",
    margin: 0,
  },
  badge: {
    padding: "6px 14px",
    background: "#2e3142",
    borderRadius: 6,
    fontSize: 14,
    fontFamily: "var(--mono)",
    color: "#c084fc",
  },
  diffContainer: {
    borderRadius: 10,
    overflow: "hidden",
    border: "1px solid #2e3142",
    marginBottom: 28,
  },
  actionPanel: {
    background: "#1a1d27",
    border: "1px solid #2e3142",
    borderRadius: 10,
    padding: 24,
  },
  actionTitle: {
    fontSize: 18,
    fontWeight: 600,
    color: "#e1e2e8",
    margin: "0 0 20px",
  },
  formRow: {
    display: "flex",
    alignItems: "center",
    gap: 12,
    marginBottom: 20,
  },
  label: {
    fontSize: 14,
    color: "#8b8fa3",
    whiteSpace: "nowrap" as const,
  },
  select: {
    flex: 1,
    padding: "10px 14px",
    background: "#0f1117",
    border: "1px solid #2e3142",
    borderRadius: 6,
    color: "#e1e2e8",
    fontSize: 14,
    outline: "none",
  },
  buttonRow: {
    display: "flex",
    gap: 12,
  },
  approveBtn: {
    flex: 1,
    padding: "12px 20px",
    background: "#2ecc71",
    color: "#fff",
    border: "none",
    borderRadius: 8,
    fontSize: 15,
    fontWeight: 600,
    cursor: "pointer",
  },
  rejectBtn: {
    flex: 1,
    padding: "12px 20px",
    background: "#e74c3c",
    color: "#fff",
    border: "none",
    borderRadius: 8,
    fontSize: 15,
    fontWeight: 600,
    cursor: "pointer",
  },
};
