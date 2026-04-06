import { useState } from "react";
import { API_BASE_URL } from "../config";

interface LoginProps {
  onLogin: () => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error ?? `Login failed (${res.status})`);
      }

      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.backdrop}>
      <form onSubmit={handleSubmit} style={styles.card}>
        <h1 style={styles.title}>Shield Claw</h1>
        <p style={styles.subtitle}>DevSecOps Audit Platform</p>

        {error && <div style={styles.error}>{error}</div>}

        <label style={styles.label} htmlFor="username">
          Username
        </label>
        <input
          id="username"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={styles.input}
          autoComplete="username"
          required
        />

        <label style={styles.label} htmlFor="password">
          Password
        </label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={styles.input}
          autoComplete="current-password"
          required
        />

        <button type="submit" disabled={loading} style={styles.button}>
          {loading ? "Authenticating..." : "Sign In"}
        </button>
      </form>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  backdrop: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    background: "#0f1117",
  },
  card: {
    display: "flex",
    flexDirection: "column",
    width: 380,
    padding: 36,
    background: "#1a1d27",
    border: "1px solid #2e3142",
    borderRadius: 12,
  },
  title: {
    fontSize: 26,
    fontWeight: 700,
    color: "#e1e2e8",
    margin: "0 0 4px",
    textAlign: "center" as const,
  },
  subtitle: {
    fontSize: 14,
    color: "#8b8fa3",
    margin: "0 0 28px",
    textAlign: "center" as const,
  },
  label: {
    fontSize: 13,
    color: "#8b8fa3",
    marginBottom: 6,
  },
  input: {
    padding: "10px 14px",
    background: "#0f1117",
    border: "1px solid #2e3142",
    borderRadius: 6,
    color: "#e1e2e8",
    fontSize: 14,
    outline: "none",
    marginBottom: 16,
  },
  button: {
    marginTop: 8,
    padding: "12px 20px",
    background: "#6c5ce7",
    color: "#fff",
    border: "none",
    borderRadius: 8,
    fontSize: 15,
    fontWeight: 600,
    cursor: "pointer",
  },
  error: {
    padding: "10px 14px",
    background: "rgba(231, 76, 60, 0.12)",
    border: "1px solid rgba(231, 76, 60, 0.3)",
    borderRadius: 8,
    marginBottom: 16,
    fontSize: 13,
    color: "#e74c3c",
    textAlign: "center" as const,
  },
};
