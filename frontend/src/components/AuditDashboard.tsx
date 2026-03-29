import { useEffect, useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import type { PullRequest } from "../types/Audit";
import TelemetryChart from "./TelemetryChart";

const OWASP_CATEGORIES = [
  "OWASP_A01 - Broken Access Control",
  "Dependency Hijack",
  "SQL Injection",
] as const;

const API_BASE = "http://localhost:8080/api/v1/audit";

export default function AuditDashboard() {
  const [pr, setPr] = useState<PullRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState(OWASP_CATEGORIES[0]);
  const [submitting, setSubmitting] = useState(false);

  const fetchPending = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/pending`);
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
  };

  useEffect(() => {
    fetchPending();
  }, []);

  const handleEvaluate = async (isApproved: boolean) => {
    if (!pr) return;
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE}/${pr.prId}/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          selectedThreatCategory: selectedCategory,
          isApproved,
        }),
      });
      if (!res.ok) throw new Error(`Evaluate failed: ${res.status}`);
      await fetchPending();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Submit error");
    } finally {
      setSubmitting(false);
    }
  };

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
        <p style={styles.error}>{error}</p>
        <button style={styles.retryBtn} onClick={fetchPending}>
          Retry
        </button>
      </div>
    );
  }

  if (!pr) {
    return (
      <div style={styles.center}>
        <p style={styles.muted}>No pending audits. You're all caught up.</p>
      </div>
    );
  }

  return (
    <div style={styles.wrapper}>
      <header style={styles.header}>
        <h1 style={styles.title}>DevSecOps Audit Dashboard</h1>
        <span style={styles.badge}>PR {pr.prId}</span>
      </header>

      {pr.threatCategory && (
        <div style={styles.threatBanner}>
          AI-detected threat: <strong>{pr.threatCategory}</strong>
        </div>
      )}

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

      <section style={styles.actionPanel}>
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
          >
            {OWASP_CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>

        <div style={styles.buttonRow}>
          <button
            disabled={submitting}
            onClick={() => handleEvaluate(true)}
            style={styles.approveBtn}
          >
            {submitting ? "Submitting…" : "Approve (No Threat)"}
          </button>
          <button
            disabled={submitting}
            onClick={() => handleEvaluate(false)}
            style={styles.rejectBtn}
          >
            {submitting ? "Submitting…" : "Reject (Vulnerability Found)"}
          </button>
        </div>
      </section>

      <TelemetryChart />
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    maxWidth: 1200,
    margin: "0 auto",
    padding: "32px 24px",
  },
  center: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    gap: 16,
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
  threatBanner: {
    padding: "10px 16px",
    background: "rgba(231, 76, 60, 0.12)",
    border: "1px solid rgba(231, 76, 60, 0.3)",
    borderRadius: 8,
    marginBottom: 20,
    fontSize: 14,
    color: "#e74c3c",
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
