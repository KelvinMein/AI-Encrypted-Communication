import { useEffect, useRef, useState } from "react";

function alertType(reason) {
  if (reason && reason.includes("exceeds learned limit")) {
    return { label: "Limit exceeded", cls: "bg-red-100 text-red-700" };
  }
  return { label: "Unusual pattern", cls: "bg-amber-100 text-amber-700" };
}

function timeAgo(iso) {
  if (!iso) return "";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return new Date(iso).toLocaleDateString();
}

export default function NotificationBell({ flags, ready, onReview, onViewAll }) {
  const [open, setOpen] = useState(false);
  const [ringing, setRinging] = useState(false);
  const wrapRef = useRef(null);
  const prevCount = useRef(null);

  const unreviewed = flags.filter((f) => !f.reviewed);
  const count = unreviewed.length;
  const shown = unreviewed.slice(0, 6);

  // Ring when the number of unreviewed alerts goes up (not on the first load)
  useEffect(() => {
    if (!ready) return;
    if (prevCount.current === null) {
      prevCount.current = count;
      return;
    }
    if (count > prevCount.current) {
      setRinging(true);
      prevCount.current = count;
      const t = setTimeout(() => setRinging(false), 1500);
      return () => clearTimeout(t);
    }
    prevCount.current = count;
  }, [count, ready]);

  // Close when clicking outside, or pressing Escape
  useEffect(() => {
    function onClick(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    }
    function onKey(e) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  return (
    <div ref={wrapRef} className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        title="Security alerts"
        aria-label={`Security alerts, ${count} unreviewed`}
        className={`relative flex h-10 w-10 items-center justify-center rounded-full transition hover:bg-slate-100 ${
          open ? "bg-slate-100" : ""
        } ${count > 0 ? "text-slate-700" : "text-slate-400"}`}
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth="1.8"
          stroke="currentColor"
          className={`h-6 w-6 ${ringing ? "bell-ring" : ""}`}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0"
          />
        </svg>

        {count > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-5 min-w-[1.25rem]">
            {ringing && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75"></span>
            )}
            <span className="relative flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-red-600 px-1 text-[11px] font-bold text-white ring-2 ring-white">
              {count > 9 ? "9+" : count}
            </span>
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 z-50 mt-2 w-96 max-w-[90vw] overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl">
          <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
            <h3 className="text-sm font-semibold text-slate-800">Notifications</h3>
            <span className="text-xs text-slate-500">
              {count === 0 ? "All caught up" : `${count} unreviewed`}
            </span>
          </div>

          {shown.length === 0 ? (
            <div className="px-4 py-10 text-center">
              <div className="mx-auto mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-emerald-100 text-xl">
                ✅
              </div>
              <p className="text-sm font-medium text-slate-700">No new alerts</p>
              <p className="text-xs text-slate-400">New alerts will show up here.</p>
            </div>
          ) : (
            <ul className="max-h-96 divide-y divide-slate-100 overflow-y-auto">
              {shown.map((f) => {
                const t = alertType(f.reason);
                return (
                  <li key={f.id} className="px-4 py-3 hover:bg-slate-50">
                    <div className="flex items-center justify-between gap-2">
                      <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${t.cls}`}>
                        {t.label}
                      </span>
                      <span className="text-[11px] text-slate-400">{timeAgo(f.flagged_at)}</span>
                    </div>
                    <p className="mt-1 truncate text-sm font-medium text-slate-800">{f.subject}</p>
                    <p className="mt-0.5 line-clamp-2 text-xs text-slate-500">{f.reason}</p>
                    <button
                      onClick={() => onReview(f.id)}
                      className="mt-2 rounded-md bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700 transition hover:bg-indigo-100"
                    >
                      Mark reviewed
                    </button>
                  </li>
                );
              })}
            </ul>
          )}

          <button
            onClick={() => {
              setOpen(false);
              onViewAll();
            }}
            className="block w-full border-t border-slate-100 bg-slate-50 px-4 py-3 text-center text-sm font-medium text-indigo-600 transition hover:bg-slate-100"
          >
            View all security alerts
            {count > shown.length ? ` (${count - shown.length} more)` : ""}
          </button>
        </div>
      )}
    </div>
  );
}