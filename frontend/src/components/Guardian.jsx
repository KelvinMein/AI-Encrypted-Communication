import { useEffect, useRef, useState } from "react";
import { explainAlert, answer } from "../utils/guardian";

const BANNER = {
  good: "border-emerald-200 bg-emerald-50 text-emerald-800",
  notice: "border-amber-200 bg-amber-50 text-amber-800",
  warning: "border-red-200 bg-red-50 text-red-800",
};

const ICON = {
  ok: { sym: "✓", cls: "bg-emerald-100 text-emerald-700" },
  warn: { sym: "!", cls: "bg-amber-100 text-amber-700" },
  bad: { sym: "✕", cls: "bg-red-100 text-red-700" },
  info: { sym: "i", cls: "bg-slate-100 text-slate-500" },
};

const BASE_CHIPS = ["Is my chat safe?", "What should I do?", "How do I spot a scam?", "What is a fingerprint?"];

export default function Guardian({ open, onClose, assessment, isAdmin, onOpenAlerts }) {
  const [thread, setThread] = useState([
    {
      from: "guardian",
      text: "Hi, I'm your Security Guardian. I check this session as you chat and explain what I find. Ask me anything about your security.",
    },
  ]);
  const [input, setInput] = useState("");
  const endRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    function onKey(e) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [thread.length, open]);

  if (!open) return null;

  const chips = isAdmin ? [...BASE_CHIPS, "What do the alerts mean?"] : BASE_CHIPS;

  function ask(text) {
    const q = text.trim();
    if (!q) return;
    setThread((t) => [...t, { from: "you", text: q }, { from: "guardian", text: answer(q, assessment, isAdmin) }]);
    setInput("");
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-slate-900/30" onClick={onClose} />

      <aside className="relative flex h-full w-full max-w-md flex-col bg-white shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-200 px-5 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-600 text-xl text-white">
              🛡️
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">Security Guardian</h2>
              <p className="text-xs text-slate-500">Rule-based assistant. Runs in your browser; nothing is sent anywhere.</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-lg px-2 py-1 text-lg text-slate-400 transition hover:bg-slate-100 hover:text-slate-700"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto px-5 py-4">
          {/* Status */}
          <div className={`rounded-xl border px-4 py-3 ${BANNER[assessment.level]}`}>
            <p className="text-sm font-semibold">{assessment.headline}</p>
          </div>

          {/* Checks */}
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">What I checked</h3>
            <ul className="space-y-2.5">
              {assessment.checks.map((c, i) => (
                <li key={i} className="flex gap-3">
                  <span
                    className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${ICON[c.state].cls}`}
                  >
                    {ICON[c.state].sym}
                  </span>
                  <div>
                    <p className="text-sm font-medium text-slate-800">{c.label}</p>
                    <p className="text-xs text-slate-500">{c.detail}</p>
                  </div>
                </li>
              ))}
            </ul>
          </section>

          {/* Recommendations */}
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Recommendations</h3>
            <ul className="list-disc space-y-1.5 pl-5 text-sm text-slate-700">
              {assessment.tips.map((t, i) => (
                <li key={i}>{t}</li>
              ))}
            </ul>
          </section>

          {/* Alerts explained (administrator only) */}
          {isAdmin && assessment.unreviewed.length > 0 && (
            <section>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                Latest alerts explained
              </h3>
              <div className="space-y-3">
                {assessment.unreviewed.slice(0, 3).map((f) => {
                  const e = explainAlert(f);
                  return (
                    <div key={f.id} className="rounded-xl border border-slate-200 p-3">
                      <p className="text-sm font-semibold text-slate-800">{e.title}</p>
                      <p className="text-xs text-slate-400">Account: {f.subject}</p>
                      <p className="mt-2 text-xs text-slate-600">
                        <span className="font-semibold">What it means: </span>
                        {e.meaning}
                      </p>
                      <p className="mt-1 text-xs text-slate-600">
                        <span className="font-semibold">What to do: </span>
                        {e.action}
                      </p>
                    </div>
                  );
                })}
                <button
                  onClick={onOpenAlerts}
                  className="w-full rounded-lg border border-indigo-200 bg-indigo-50 py-2 text-sm font-medium text-indigo-700 transition hover:bg-indigo-100"
                >
                  Open Security alerts
                </button>
              </div>
            </section>
          )}

          {/* Ask Guardian */}
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Ask Guardian</h3>
            <div className="space-y-2">
              {thread.map((m, i) => (
                <div key={i} className={`flex ${m.from === "you" ? "justify-end" : "justify-start"}`}>
                  <div
                    className={`max-w-[88%] rounded-2xl px-3 py-2 text-sm ${
                      m.from === "you"
                        ? "rounded-br-md bg-indigo-600 text-white"
                        : "rounded-bl-md bg-slate-100 text-slate-800"
                    }`}
                  >
                    {m.text}
                  </div>
                </div>
              ))}
              <div ref={endRef} />
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {chips.map((c) => (
                <button
                  key={c}
                  onClick={() => ask(c)}
                  className="rounded-full border border-slate-300 px-3 py-1 text-xs text-slate-600 transition hover:bg-slate-100"
                >
                  {c}
                </button>
              ))}
            </div>
          </section>
        </div>

        {/* Question box */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            ask(input);
          }}
          className="flex items-center gap-2 border-t border-slate-200 px-4 py-3"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask a security question..."
            className="flex-1 rounded-full border border-slate-300 bg-slate-50 px-4 py-2 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-500 focus:bg-white focus:ring-4 focus:ring-indigo-100"
          />
          <button
            type="submit"
            disabled={!input.trim()}
            className="rounded-full bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300"
          >
            Ask
          </button>
        </form>
      </aside>
    </div>
  );
}