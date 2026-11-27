import { useEffect, useState } from "react";

const API = "http://127.0.0.1:8000";

function when(iso) {
  if (!iso) return "";
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

export default function SecurityCentre({ token }) {
  const [sessions, setSessions] = useState([]);
  const [notes, setNotes] = useState([]);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const headers = { Authorization: `Bearer ${token}` };

  async function get(path) {
    try {
      const res = await fetch(`${API}${path}`, { headers, cache: "no-store" });
      if (res.status === 401) {
        window.location.reload(); // this session was ended elsewhere
        return null;
      }
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  async function post(path) {
    try {
      const res = await fetch(`${API}${path}`, { method: "POST", headers });
      let data = {};
      try {
        data = await res.json();
      } catch {
        data = {};
      }
      return { ok: res.ok, text: typeof data.detail === "string" ? data.detail : data.message || "" };
    } catch {
      return { ok: false, text: "Could not reach the server." };
    }
  }

  async function load() {
    const [s, n] = await Promise.all([get("/sessions"), get("/security/notifications")]);
    if (s) {
      setSessions(s);
      setError("");
    } else {
      setError("Could not load your sessions.");
    }
    if (n) setNotes(n.items);
  }

  useEffect(() => {
    load().then(() => post("/security/notifications/read"));
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  async function act(path, confirmText) {
    if (confirmText && !window.confirm(confirmText)) return;
    const r = await post(path);
    setInfo(r.text);
    load();
  }

  const unfamiliar = sessions.filter((s) => !s.confirmed && !s.current);
  const others = sessions.filter((s) => !s.current);

  return (
    <div className="mx-auto max-w-3xl space-y-8 p-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-900">Security centre</h2>
        <p className="text-sm text-slate-500">See where you are signed in and end any session you do not recognise.</p>
      </div>

      {unfamiliar.length > 0 && (
        <div className="rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-800">
          <p className="font-semibold">
            {unfamiliar.length} unfamiliar device{unfamiliar.length > 1 ? "s are" : " is"} signed in to your account.
          </p>
          <p className="mt-1">If you do not recognise it, sign it out below and change your password.</p>
        </div>
      )}

      {error && <div className="rounded-xl bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
      {info && <div className="rounded-xl bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{info}</div>}

      <section>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-500">Where you are signed in</h3>
          {others.length > 0 && (
            <button
              onClick={() =>
                act("/sessions/revoke-others", `Sign out the other ${others.length} session${others.length > 1 ? "s" : ""}?`)
              }
              className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-red-700"
            >
              Sign out all other sessions
            </button>
          )}
        </div>

        <div className="space-y-3">
          {sessions.map((s) => (
            <div
              key={s.id}
              className={`rounded-2xl border bg-white p-4 shadow-sm ${
                !s.confirmed && !s.current ? "border-red-300" : "border-slate-200"
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-semibold text-slate-800">{s.device}</p>
                    {s.current && (
                      <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-[11px] font-medium text-indigo-700">
                        This device
                      </span>
                    )}
                    {!s.confirmed && !s.current && (
                      <span className="rounded-full bg-red-100 px-2 py-0.5 text-[11px] font-medium text-red-700">
                        Unfamiliar device
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-slate-500">
                    Address {s.ip || "unknown"} · signed in {when(s.created_at)} · last active {when(s.last_seen)}
                  </p>
                </div>
                {!s.current && (
                  <div className="flex gap-2">
                    {!s.confirmed && (
                      <button
                        onClick={() => act(`/sessions/${s.id}/confirm`)}
                        className="rounded-lg border border-emerald-300 px-3 py-1.5 text-xs font-medium text-emerald-700 transition hover:bg-emerald-50"
                      >
                        This was me
                      </button>
                    )}
                    <button
                      onClick={() => act(`/sessions/${s.id}/revoke`, `Sign out ${s.device}?`)}
                      className="rounded-lg border border-red-300 px-3 py-1.5 text-xs font-medium text-red-600 transition hover:bg-red-50"
                    >
                      Sign out
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
          {sessions.length === 0 && !error && <p className="text-sm text-slate-400">Loading...</p>}
        </div>
      </section>

      <section>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">Recent security notifications</h3>
        {notes.length === 0 ? (
          <p className="rounded-2xl border border-dashed border-slate-300 px-5 py-8 text-center text-sm text-slate-400">
            Nothing to report. You will be told here, and by email, when a new device signs in.
          </p>
        ) : (
          <ul className="divide-y divide-slate-100 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            {notes.map((n) => (
              <li key={n.id} className="flex items-start justify-between gap-3 px-5 py-3 text-sm">
                <div>
                  <p className="text-slate-800">{n.message}</p>
                  <p className="text-xs text-slate-400">{when(n.created_at)}</p>
                </div>
                {!n.read && (
                  <span className="rounded-full bg-red-100 px-2 py-0.5 text-[11px] font-medium text-red-700">New</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}