import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Session {
  id: string;
  beacon_id: number;
  hostname: string;
  username: string;
  os: string;
  arch: number;
  pid: number;
  is_admin: number;
  pending: number;
}

export default function App() {
  const [server, setServer] = useState("http://127.0.0.1:8443");
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [cmd, setCmd] = useState("");
  const [out, setOut] = useState("");
  const [err, setErr] = useState("");

  const refresh = async () => {
    try {
      setSessions(await invoke<Session[]>("list_sessions", { server }));
      setErr("");
    } catch (e) {
      setErr(String(e));
    }
  };

  useEffect(() => {
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server]);

  const run = async () => {
    if (!selected) return;
    setOut("");
    setErr("");
    try {
      const result = await invoke<string>("shell", { server, session: selected, args: cmd });
      setOut(result);
    } catch (e) {
      setErr(String(e));
    }
  };

  const kill = async () => {
    if (!selected) return;
    try {
      await invoke("exit_session", { server, session: selected });
      setOut("[exit tasked]");
    } catch (e) {
      setErr(String(e));
    }
  };

  return (
    <div className="app">
      <header>
        <h1>Nyx</h1>
        <input value={server} onChange={(e) => setServer(e.target.value)} placeholder="team server URL" />
        <button onClick={refresh}>refresh</button>
      </header>
      <main>
        <section className="sessions">
          <h2>Sessions</h2>
          <table>
            <thead>
              <tr>
                <th>Beacon</th><th>Host</th><th>User</th><th>OS</th><th>Adm</th><th>Queued</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr
                  key={s.id}
                  className={s.id === selected ? "sel" : ""}
                  onClick={() => setSelected(s.id)}
                >
                  <td>{s.beacon_id}</td>
                  <td>{s.hostname}</td>
                  <td>{s.username}</td>
                  <td>{s.os}</td>
                  <td>{s.is_admin ? "●" : ""}</td>
                  <td>{s.pending}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
        <section className="console">
          <h2>Console {selected && <code>{selected.slice(0, 8)}</code>}</h2>
          <div className="input">
            <input
              value={cmd}
              onChange={(e) => setCmd(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
              placeholder={selected ? "shell command (e.g. whoami /groups)" : "select a session first"}
              disabled={!selected}
            />
            <button onClick={run} disabled={!selected || !cmd}>run</button>
            <button onClick={kill} disabled={!selected}>exit</button>
          </div>
          {err && <pre className="err">{err}</pre>}
          <pre className="out">{out}</pre>
        </section>
      </main>
    </div>
  );
}
