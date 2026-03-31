import { useCallback, useEffect, useState } from "react";
import AuditDashboard from "./components/AuditDashboard";
import Login from "./components/Login";

function App() {
  const [authed, setAuthed] = useState<boolean | null>(null);

  const checkSession = useCallback(async () => {
    try {
      const res = await fetch("http://localhost:8080/api/v1/auth/me", {
        credentials: "include",
      });
      setAuthed(res.ok);
    } catch {
      setAuthed(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  const handleLogout = useCallback(async () => {
    await fetch("http://localhost:8080/api/v1/auth/logout", {
      method: "POST",
      credentials: "include",
    });
    setAuthed(false);
  }, []);

  const handleLogin = useCallback(() => {
    setAuthed(true);
  }, []);

  if (authed === null) {
    return (
      <div style={styles.loading}>
        <p style={styles.muted}>Verifying session…</p>
      </div>
    );
  }

  if (!authed) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div>
      <nav style={styles.topBar} aria-label="Primary navigation">
        <button
          onClick={handleLogout}
          style={styles.logoutBtn}
          aria-label="Sign out of the dashboard"
        >
          Logout
        </button>
      </nav>
      <AuditDashboard onUnauthorized={handleLogout} />
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  loading: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    background: "#0f1117",
  },
  muted: {
    color: "#8b8fa3",
    fontSize: 16,
  },
  topBar: {
    display: "flex",
    justifyContent: "flex-end",
    padding: "12px 24px",
    maxWidth: 1200,
    margin: "0 auto",
  },
  logoutBtn: {
    padding: "6px 16px",
    background: "transparent",
    border: "1px solid #2e3142",
    borderRadius: 6,
    color: "#8b8fa3",
    fontSize: 13,
    cursor: "pointer",
  },
};

export default App;
