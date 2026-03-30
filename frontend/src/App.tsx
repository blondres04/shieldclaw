import { useCallback, useState } from "react";
import AuditDashboard from "./components/AuditDashboard";
import Login from "./components/Login";

function App() {
  const [token, setToken] = useState<string | null>(
    localStorage.getItem("token"),
  );

  const handleLogout = useCallback(() => {
    localStorage.removeItem("token");
    setToken(null);
  }, []);

  if (!token) {
    return <Login onLogin={setToken} />;
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
