function alertType(reason) {
  if (reason && reason.includes("exceeds learned limit")) {
    return { label: "Limit exceeded", cls: "bg-red-100 text-red-700" };
  }
  return { label: "Unusual pattern", cls: "bg-amber-100 text-amber-700" };
}

function StatCard({ label, value, tone }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-bold ${tone}`}>{value}</p>
    </div>
  );
}

export default function AlertsPanel({ flags, error, showReviewed, setShowReviewed, onReview }) {
  const unreviewed = flags.filter((f) => !f.reviewed).length;
  const visible = flags.filter((f) => showReviewed || !f.reviewed);
  const latest = flags.length && flags[0].flagged_at ? new Date(flags[0].flagged_at).toLocaleTimeString() : "None";

  return (
    <div className="mx-auto max-w-6xl p-6">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-slate-900">Security alerts</h2>
          <p className="text-sm text-slate-500">
            Raised by the AI detector from activity metadata. This page refreshes every 5 seconds.
          </p>
        </div>
        <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-600">
          <input
            type="checkbox"
            checked={showReviewed}
            onChange={(e) => setShowReviewed(e.target.checked)}
            className="h-4 w-4 rounded border-slate-300 text-indigo-600"
          />
          Show reviewed alerts
        </label>
      </div>

      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <StatCard label="Unreviewed" value={unreviewed} tone={unreviewed ? "text-red-600" : "text-emerald-600"} />
        <StatCard label="Total alerts" value={flags.length} tone="text-slate-800" />
        <StatCard label="Latest alert" value={latest} tone="text-slate-800" />
      </div>

      {error && (
        <div className="mb-4 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
      )}

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        {!error && visible.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 text-2xl">
              ✅
            </div>
            <p className="font-medium text-slate-700">No alerts to review</p>
            <p className="text-sm text-slate-400">New alerts appear here automatically.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-5 py-3 font-medium">Time</th>
                  <th className="px-5 py-3 font-medium">Account</th>
                  <th className="px-5 py-3 font-medium">Type</th>
                  <th className="px-5 py-3 font-medium">What was detected</th>
                  <th className="px-5 py-3 font-medium">Score</th>
                  <th className="px-5 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {visible.map((f) => {
                  const t = alertType(f.reason);
                  return (
                    <tr key={f.id} className={f.reviewed ? "opacity-50" : "hover:bg-slate-50"}>
                      <td className="whitespace-nowrap px-5 py-3 text-slate-600">
                        {f.flagged_at ? new Date(f.flagged_at).toLocaleTimeString() : ""}
                      </td>
                      <td className="px-5 py-3 font-medium text-slate-800">{f.subject}</td>
                      <td className="px-5 py-3">
                        <span className={`whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-medium ${t.cls}`}>
                          {t.label}
                        </span>
                      </td>
                      <td className="max-w-md px-5 py-3 text-slate-600">{f.reason}</td>
                      <td className="px-5 py-3 font-mono text-slate-600">{f.anomaly_score.toFixed(2)}</td>
                      <td className="px-5 py-3 text-right">
                        {f.reviewed ? (
                          <span className="text-xs text-slate-400">Reviewed</span>
                        ) : (
                          <button
                            onClick={() => onReview(f.id)}
                            className="whitespace-nowrap rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-indigo-700"
                          >
                            Mark reviewed
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}