import { useEffect, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import type { TelemetryStats } from "../types/Audit";

const STATUS_COLORS: Record<string, string> = {
  PENDING_AUDIT: "#f1c40f",
  AUDIT_PASSED: "#2ecc71",
  AUDIT_FAILED_FALSE_POSITIVE: "#e74c3c",
  AUDIT_FAILED_MISSED_THREAT: "#e67e22",
};

const FALLBACK_COLOR = "#6c5ce7";

const LABEL_MAP: Record<string, string> = {
  PENDING_AUDIT: "Pending",
  AUDIT_PASSED: "Passed",
  AUDIT_FAILED_FALSE_POSITIVE: "False Positive",
  AUDIT_FAILED_MISSED_THREAT: "Missed Threat",
};

interface ChartEntry {
  name: string;
  value: number;
  color: string;
}

export default function TelemetryChart() {
  const [data, setData] = useState<ChartEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("http://localhost:8080/api/v1/telemetry/stats")
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json() as Promise<TelemetryStats>;
      })
      .then((stats) => {
        const entries: ChartEntry[] = Object.entries(stats.statusCounts).map(
          ([key, value]) => ({
            name: LABEL_MAP[key] ?? key,
            value,
            color: STATUS_COLORS[key] ?? FALLBACK_COLOR,
          }),
        );
        setData(entries);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Fetch error"));
  }, []);

  if (error) {
    return (
      <div style={styles.container}>
        <p style={styles.error}>Telemetry unavailable: {error}</p>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div style={styles.container}>
        <p style={styles.muted}>No telemetry data yet.</p>
      </div>
    );
  }

  return (
    <section style={styles.container}>
      <h2 style={styles.heading}>Audit Telemetry</h2>
      <ResponsiveContainer width="100%" height={320}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={70}
            outerRadius={120}
            paddingAngle={3}
            strokeWidth={0}
            label={({ name, percent }) =>
              `${name} ${(percent * 100).toFixed(0)}%`
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
    </section>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    background: "#1a1d27",
    border: "1px solid #2e3142",
    borderRadius: 10,
    padding: 24,
    marginTop: 28,
  },
  heading: {
    fontSize: 18,
    fontWeight: 600,
    color: "#e1e2e8",
    margin: "0 0 16px",
  },
  muted: {
    color: "#8b8fa3",
    fontSize: 14,
    textAlign: "center" as const,
  },
  error: {
    color: "#e74c3c",
    fontSize: 14,
    textAlign: "center" as const,
  },
};
