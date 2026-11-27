import { useState } from "react";

const REASONS = [
  ["insult", "Insults or harassment"],
  ["threat", "Threats or intimidation"],
  ["scam", "Scam, phishing or spam"],
  ["inappropriate", "Inappropriate content"],
  ["other", "Something else"],
];

export default function ReportDialog({ target, onClose, onSubmit }) {
  const [reason, setReason] = useState("insult");
  const [details, setDetails] = useState("");
  const [includeText, setIncludeText] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const res = await onSubmit(target, { reason, details: details.trim(), includeText });
    setBusy(false);
    if (res.ok) setDone(true);
    else setError(res.message || "Could not send the report.");
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 px-4" onClick={onClose}>
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        {done ? (
          <div className="text-center">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 text-2xl">✓</div>
            <h3 className="text-lg font-bold text-slate-900">Report sent</h3>
            <p className="mt-1 text-sm text-slate-500">An administrator will review it. Thank you for helping keep this space safe.</p>
            <button
              onClick={onClose}
              className="mt-5 w-full rounded-xl bg-indigo-600 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-700"
            >
              Close
            </button>
          </div>
        ) : (
          <form onSubmit={submit}>
            <h3 className="text-lg font-bold text-slate-900">Report a message from {target.from}</h3>

            <div className="mt-3 rounded-xl bg-slate-100 px-3 py-2 text-sm text-slate-700">
              <p className="line-clamp-3 whitespace-pre-wrap break-words">{target.text}</p>
            </div>

            <label className="mt-4 block text-sm font-medium text-slate-700">Reason</label>
            <select
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="mt-1.5 w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100"
            >
              {REASONS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>

            <label className="mt-4 block text-sm font-medium text-slate-700">Anything to add? (optional)</label>
            <textarea
              value={details}
              onChange={(e) => setDetails(e.target.value)}
              maxLength={500}
              rows={3}
              className="mt-1.5 w-full resize-none rounded-xl border border-slate-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100"
              placeholder="Context that helps the administrator"
            />

            <label className="mt-4 flex cursor-pointer items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 px-3 py-3 text-xs text-amber-900">
              <input
                type="checkbox"
                checked={includeText}
                onChange={(e) => setIncludeText(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600"
              />
              <span>
                <span className="font-semibold">Include the message text for the administrator.</span> Messages are
                encrypted, so administrators cannot read them unless you share. The server cannot check that the text
                you share is genuine.
              </span>
            </label>

            {error && <p className="mt-3 rounded-xl bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

            <div className="mt-5 flex gap-3">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 rounded-xl border border-slate-300 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={busy}
                className="flex-1 rounded-xl bg-red-600 py-2.5 text-sm font-semibold text-white transition hover:bg-red-700 disabled:opacity-60"
              >
                {busy ? "Sending..." : "Send report"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}