import { useCallback, useEffect, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import type { TelemetryStats } from "../types/Audit";

const STATS_URL = "http://localhost:8080/api/v1/audit/stats";

const STATUS_COLORS: Record<string, string> = {
  PENDING_AUDIT: "#f1c40f",
  IN_REVIEW: "#3498db",
  AUDIT_PASSED: "#2ecc71",
  AUDIT_FAILED_FALSE_POSITIVE: "#e74c3c",
  AUDIT_FAILED_MISSED_THREAT: "#e67e22",
};

const FALLBACK_COLOR = "#6c5ce7";

const LABEL_MAP: Record<string, string> = {
  PENDING_AUDIT: "Pending",
  IN_REVIEW: "In Review",
  AUDIT_PASSED: "Passed",
  AUDIT_FAILED_FALSE_POSITIVE: "False Positive",
  AUDIT_FAILED_MISSED_THREAT: "Missed Threat",
};

interface ChartEntry {
  name: string;
  value: number;
  color: string;
}

interface TelemetryChartProps {
  onUnauthorized: () => void;
}

function mapStatusCountsToChartEntries(
  statusCounts: Record<string, number> | undefined,
): ChartEntry[] {
  if (!statusCounts || Object.keys(statusCounts).length === 0) {
    return [];
  }
  return Object.entries(statusCounts).map(([key, value]) => ({
    name: LABEL_MAP[key] ?? key,
    value: Number(value) || 0,
    color: STATUS_COLORS[key] ?? FALLBACK_COLOR,
  }));
}

export default function TelemetryChart({ onUnauthorized }: TelemetryChartProps) {
  const [data, setData] = useState<ChartEntry[]>([]);
  const [verifiedExploits, setVerifiedExploits] = useState(0);
  const [failedExploits, setFailedExploits] = useState(0);

  const loadStats = useCallback(async () => {
    try {
      const res = await fetch(STATS_URL, {
        credentials: "include",
      });
      if (res.status === 401 || res.status === 403) {
        onUnauthorized();
        return;
      }
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const stats = (await res.json()) as TelemetryStats;
      setData(mapStatusCountsToChartEntries(stats.statusCounts));
      setVerifiedExploits(
        stats.verifiedExploits != null ? Number(stats.verifiedExploits) : 0,
      );
      setFailedExploits(
        stats.failedExploits != null ? Number(stats.failedExploits) : 0,
      );
    } catch {
      setData([]);
      setVerifiedExploits(0);
      setFailedExploits(0);
    }
  }, [onUnauthorized]);

  useEffect(() => {
    void loadStats();
    const intervalId = window.setInterval(() => {
      void loadStats();
    }, 10_000);
    return () => window.clearInterval(intervalId);
  }, [loadStats]);

  return (
    <section style={styles.container} role="region" aria-label="Audit telemetry">
      <h2 style={styles.heading}>Audit Telemetry</h2>

      {data.length > 0 ? (
        <div style={styles.chartWrapper}>
          <ResponsiveContainer width="100%" height={350}>
            <PieChart margin={{ top: 20, right: 40, bottom: 20, left: 40 }}>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={3}
                strokeWidth={0}
                label={({ name, percent }) =>
                  `${name} ${((percent || 0) * 100).toFixed(0)}%`
                }
              >
                {data.map((entry, i) => (
                  <Cell key={`cell-${i}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#1a1d27",
                  border: "1px solid #2e3142",
                  borderRadius: 8,
                  color: "#e1e2e8",
                }}
              />
              <Legend
                wrapperStyle={{ color: "#8b8fa3", fontSize: 13 }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <p style={styles.muted}>No telemetry data yet.</p>
      )}

      <div style={styles.metricsRow} aria-label="Sandbox verification totals">
        <div style={styles.metricCard}>
          <span style={styles.metricLabel}>Sandbox verified (success)</span>
          <span style={styles.metricValueVerified}>{verifiedExploits}</span>
        </div>
        <div style={styles.metricCard}>
          <span style={styles.metricLabel}>Sandbox verified (failed)</span>
          <span style={styles.metricValueFailed}>{failedExploits}</span>
        </div>
      </div>
    </section>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    background: "#1a1d27",
    border: "1px solid #2e3142",
    borderRadius: 10,
    padding: "24px 16px",
    marginTop: 28,
  },
  chartWrapper: {
    width: "100%",
    minHeight: 350,
  },
  heading: {
    fontSize: 18,
    fontWeight: 600,
    color: "#e1e2e8",
    margin: "0 0 8px",
    paddingLeft: 24,
  },
  muted: {
    color: "#8b8fa3",
    fontSize: 14,
    textAlign: "center" as const,
    marginBottom: 16,
  },
  metricsRow: {
    display: "flex",
    flexWrap: "wrap" as const,
    gap: 12,
    justifyContent: "center",
    marginTop: 20,
    paddingLeft: 24,
    paddingRight: 24,
  },
  metricCard: {
    flex: "1 1 140px",
    maxWidth: 220,
    background: "#13151d",
    border: "1px solid #2e3142",
    borderRadius: 8,
    padding: "14px 18px",
    display: "flex",
    flexDirection: "column" as const,
    gap: 6,
  },
  metricLabel: {
    fontSize: 12,
    color: "#8b8fa3",
    textTransform: "uppercase" as const,
    letterSpacing: "0.04em",
  },
  metricValueVerified: {
    fontSize: 22,
    fontWeight: 700,
    color: "#2ecc71",
    fontFamily: "var(--mono)",
  },
  metricValueFailed: {
    fontSize: 22,
    fontWeight: 700,
    color: "#e74c3c",
    fontFamily: "var(--mono)",
  },
};
