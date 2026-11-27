import { useState } from "react";

const LABEL = {
  insult: "Insults or harassment",
  threat: "Threats",
  scam: "Scam or phishing",
  inappropriate: "Inappropriate",
  other: "Other",
};
const TONE = {
  insult: "bg-red-100 text-red-700",
  threat: "bg-red-100 text-red-700",
  scam: "bg-amber-100 text-amber-700",
  inappropriate: "bg-amber-100 text-amber-700",
  other: "bg-slate-100 text-slate-600",
};
const STATUS = {
  open: ["Open", "bg-indigo-100 text-indigo-700"],
  dismissed: ["Dismissed", "bg-slate-100 text-slate-600"],
  actioned: ["Action taken", "bg-emerald-100 text-emerald-700"],
};

function ReportCard({ r, onDismiss, onDeactivate }) {
  const [mode, setMode] = useState(null); // "dismiss" | "deactivate"
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const open = r.status === "open";

  async function confirm() {
    if (mode === "deactivate" && !text.trim()) return setError("Please give a reason.");
    setBusy(true);
    setError("");
    const res = mode === "dismiss" ? await onDismiss(r.id, text.trim()) : await onDeactivate(r.reported_user_id, text.trim());
    setBusy(false);
    if (!res.ok) setError(res.message || "That did not work.");
    else setMode(null);
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${TONE[r.reason] || TONE.other}`}>
            {LABEL[r.reason] || r.reason}
          </span>
          <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${STATUS[r.status]?.[1]}`}>
            {STATUS[r.status]?.[0] || r.status}
          </span>
        </div>
        <span className="text-xs text-slate-400">{r.created_at ? new Date(r.created_at).toLocaleString() : ""}</span>
      </div>

      <p className="mt-3 text-sm text-slate-700">
        <span className="font-semibold">{r.reporter}</span> reported <span className="font-semibold">{r.reported}</span>
        {!r.reported_active && <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-500">deactivated</span>}
      </p>
      <p className="mt-1 text-xs text-slate-400">
        {r.reported} has been reported {r.reported_total} time{r.reported_total === 1 ? "" : "s"} in total.
      </p>

      {r.details && <p className="mt-3 text-sm text-slate-600">"{r.details}"</p>}

      <div className="mt-3 rounded-xl bg-slate-50 px-4 py-3">
        {r.evidence_text ? (
          <>
            <p className="whitespace-pre-wrap break-words text-sm text-slate-800">{r.evidence_text}</p>
            <p className="mt-2 text-[11px] text-slate-400">
              Message text shared by the reporter. The server cannot read messages, so it cannot confirm this is
              genuine. Use your judgement.
            </p>
          </>
        ) : (
          <p className="text-sm text-slate-500">The reporter did not include the message text.</p>
        )}
      </div>

      {r.resolution_note && !open && <p className="mt-3 text-xs text-slate-500">Resolution: {r.resolution_note}</p>}

      {open && !mode && (
        <div className="mt-4 flex flex-wrap gap-2">
          <button
            onClick={() => setMode("dismiss")}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-50"
          >
            Dismiss
          </button>
          {r.reported_active && (
            <button
              onClick={() => setMode("deactivate")}
              className="rounded-lg bg-red-600 px-3 py-1.5 text-sm font-semibold text-white transition hover:bg-red-700"
            >
              Deactivate account
            </button>
          )}
        </div>
      )}

      {open && mode && (
        <div className="mt-4 rounded-xl border border-slate-200 p-3">
          <p className="text-sm font-medium text-slate-700">
            {mode === "deactivate" ? `Deactivate ${r.reported}? They will be logged out and unable to log in.` : "Dismiss this report?"}
          </p>
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            maxLength={300}
            placeholder={mode === "deactivate" ? "Reason (required)" : "Note (optional)"}
            className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100"
          />
          {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
          <div className="mt-3 flex gap-2">
            <button
              onClick={() => {
                setMode(null);
                setText("");
                setError("");
              }}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
            >
              Cancel
            </button>
            <button
              onClick={confirm}
              disabled={busy}
              className={`rounded-lg px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-60 ${
                mode === "deactivate" ? "bg-red-600 hover:bg-red-700" : "bg-indigo-600 hover:bg-indigo-700"
              }`}
            >
              {busy ? "Working..." : "Confirm"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ReportsPanel({ reports, error, onDismiss, onDeactivate }) {
  const [tab, setTab] = useState("open");
  const openCount = reports.filter((r) => r.status === "open").length;
  const shown = reports.filter((r) => (tab === "open" ? r.status === "open" : r.status !== "open"));

  return (
    <div className="mx-auto max-w-3xl p-6">
      <h2 className="text-2xl font-bold text-slate-900">Reports</h2>
      <p className="text-sm text-slate-500">Messages that people reported. Review each one and decide what to do.</p>

      <div className="mt-5 inline-flex rounded-xl bg-slate-100 p-1 text-sm font-medium">
        <button
          onClick={() => setTab("open")}
          className={`rounded-lg px-4 py-1.5 transition ${tab === "open" ? "bg-white text-indigo-600 shadow-sm" : "text-slate-500"}`}
        >
          Open ({openCount})
        </button>
        <button
          onClick={() => setTab("resolved")}
          className={`rounded-lg px-4 py-1.5 transition ${tab === "resolved" ? "bg-white text-indigo-600 shadow-sm" : "text-slate-500"}`}
        >
          Resolved ({reports.length - openCount})
        </button>
      </div>

      {error && <div className="mt-4 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}

      <div className="mt-5 space-y-4">
        {shown.length === 0 && !error && (
          <div className="rounded-2xl border border-dashed border-slate-300 px-6 py-14 text-center">
            <p className="font-medium text-slate-700">{tab === "open" ? "No open reports" : "Nothing resolved yet"}</p>
            <p className="text-sm text-slate-400">New reports appear here automatically.</p>
          </div>
        )}
        {shown.map((r) => (
          <ReportCard key={r.id} r={r} onDismiss={onDismiss} onDeactivate={onDeactivate} />
        ))}
      </div>
    </div>
  );
}