import { useEffect, useMemo, useRef, useState } from "react";
import { defang, toHref } from "../utils/linkScan";
import { analyse } from "../utils/phishing";
import ReportDialog from "./ReportDialog";

const COLORS = ["bg-indigo-500", "bg-sky-500", "bg-emerald-500", "bg-amber-500", "bg-rose-500", "bg-violet-500"];

function colorFor(name) {
  let h = 0;
  for (const c of name) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return COLORS[h % COLORS.length];
}

// "email" is the prop name kept from earlier versions; it now receives a username
export function Avatar({ email, size = "h-10 w-10 text-sm" }) {
  const name = email || "?";
  return (
    <div
      className={`flex shrink-0 items-center justify-center rounded-full font-semibold uppercase text-white ${size} ${colorFor(name)}`}
    >
      {name.charAt(0)}
    </div>
  );
}

function formatTime(t) {
  if (!t) return "";
  return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// Renders one message. Received messages are scanned for suspicious links and wording.
function MessageBody({ text, mine }) {
  const [reveal, setReveal] = useState(false);
  const scan = useMemo(() => (mine ? null : analyse(text)), [text, mine]);

  if (mine) {
    return (
      <div className="whitespace-pre-wrap break-words rounded-2xl rounded-br-md bg-indigo-600 px-4 py-2 text-sm text-white shadow-sm">
        {text}
      </div>
    );
  }

  const risky = scan.level === "medium" || scan.level === "high";
  const hideLinks = risky && !reveal;
  const high = scan.level === "high";

  return (
    <div>
      <div
        className={`whitespace-pre-wrap break-words rounded-2xl rounded-bl-md border bg-white px-4 py-2 text-sm text-slate-800 shadow-sm ${
          risky ? (high ? "border-red-300" : "border-amber-300") : "border-slate-200"
        }`}
      >
        {scan.parts.map((p, i) => {
          if (p.type === "text") return <span key={i}>{p.value}</span>;
          if (hideLinks) {
            return (
              <span key={i} className="break-all rounded bg-red-100 px-1 font-mono text-xs text-red-800">
                {defang(p.value)}
              </span>
            );
          }
          return (
            <a
              key={i}
              href={toHref(p.value)}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="break-all text-indigo-600 underline"
            >
              {p.value}
            </a>
          );
        })}
      </div>

      {risky && (
        <div
          className={`mt-2 rounded-xl border px-3 py-2 text-xs ${
            high ? "border-red-300 bg-red-50 text-red-800" : "border-amber-300 bg-amber-50 text-amber-800"
          }`}
        >
          <p className="font-semibold">{high ? "Likely suspicious message" : "This message may be suspicious"}</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4">
            {scan.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          <p className="mt-1">Do not enter passwords, PINs or payment details on a site you reached from a message.</p>
          {scan.links.length > 0 && (
            <button
              onClick={() => setReveal((r) => !r)}
              className="mt-2 rounded-md border border-current px-2 py-1 font-medium"
            >
              {reveal ? "Hide links again" : "Show links anyway"}
            </button>
          )}
        </div>
      )}

      {!risky && scan.level === "low" && (
        <p className="mt-1 text-[11px] text-amber-700">
          This message contains a link. Check where it goes before opening it.
        </p>
      )}
    </div>
  );
}

export default function Chat({
  users,
  unread = {},
  recipientEmail, // the selected contact's username
  onSelect,
  recipientFingerprint,
  messages,
  messageText,
  setMessageText,
  onSend,
  onReplay,
  reported = {},
  onReport,
}) {
  const bottomRef = useRef(null);
  const [reportTarget, setReportTarget] = useState(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages.length, recipientEmail]);

  return (
    <div className="flex h-full flex-col md:flex-row">
      {/* Contacts sidebar */}
      <aside className="flex max-h-48 w-full shrink-0 flex-col border-b border-slate-200 bg-white md:max-h-none md:w-72 md:border-b-0 md:border-r">
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">Contacts</h2>
        </div>
        <div className="flex-1 overflow-y-auto">
          {users.length === 0 && (
            <p className="px-5 py-4 text-sm text-slate-400">No other users with uploaded keys yet.</p>
          )}
          {users.map((u) => {
            const count = unread[u.username] || 0;
            return (
              <button
                key={u.username}
                onClick={() => onSelect(u.username)}
                className={`flex w-full items-center gap-3 px-5 py-3 text-left transition hover:bg-slate-50 ${
                  recipientEmail === u.username ? "bg-indigo-50" : ""
                }`}
              >
                <Avatar email={u.username} />
                <div className="min-w-0 flex-1">
                  <p className={`truncate text-sm text-slate-800 ${count > 0 ? "font-bold" : "font-medium"}`}>
                    {u.username}
                  </p>
                  <p className={`text-xs ${count > 0 ? "font-medium text-indigo-600" : "text-slate-400"}`}>
                    {count > 0 ? `${count} new message${count > 1 ? "s" : ""}` : "Encrypted chat"}
                  </p>
                </div>
                {count > 0 && (
                  <span className="flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-indigo-600 px-1.5 text-[11px] font-semibold text-white">
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </aside>

      {/* Conversation */}
      <section className="flex min-h-0 flex-1 flex-col bg-slate-50">
        {!recipientEmail ? (
          <div className="flex flex-1 flex-col items-center justify-center px-6 text-center">
            <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-indigo-100 text-3xl">💬</div>
            <h3 className="text-lg font-semibold text-slate-700">Select a contact to start chatting</h3>
            <p className="mt-1 max-w-sm text-sm text-slate-500">
              Messages are encrypted in your browser before they are sent. The server only ever sees ciphertext.
            </p>
          </div>
        ) : (
          <>
            <header className="flex items-center justify-between gap-3 border-b border-slate-200 bg-white px-5 py-3">
              <div className="flex min-w-0 items-center gap-3">
                <Avatar email={recipientEmail} />
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-slate-800">{recipientEmail}</p>
                  {recipientFingerprint ? (
                    <p className="truncate text-xs text-slate-500">
                      Key fingerprint{" "}
                      <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-700">
                        {recipientFingerprint}
                      </code>
                    </p>
                  ) : (
                    <p className="text-xs text-slate-400">Loading keys...</p>
                  )}
                </div>
              </div>
              <button
                onClick={onReplay}
                title="Re-sends your last message to demonstrate replay protection"
                className="shrink-0 rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:bg-slate-100"
              >
                Test replay attack
              </button>
            </header>

            {recipientFingerprint && (
              <div className="border-b border-amber-100 bg-amber-50 px-5 py-2 text-xs text-amber-800">
                Compare this fingerprint with {recipientEmail} in person or by phone to confirm nobody is intercepting
                your messages.
              </div>
            )}

            <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
              {messages.length === 0 && (
                <p className="pt-8 text-center text-sm text-slate-400">No messages yet. Say hello!</p>
              )}
              {messages.map((m, i) => {
                if (m.rejected || m.system) {
                  return (
                    <div key={i} className="flex justify-center">
                      <span
                        className={`rounded-full px-3 py-1 text-xs ${
                          m.rejected ? "bg-amber-100 text-amber-800" : "bg-slate-200 text-slate-600"
                        }`}
                      >
                        {m.text}
                      </span>
                    </div>
                  );
                }
                const mine = m.from === "me";
                return (
                  <div key={i} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
                    <div className="max-w-[75%]">
                      <MessageBody text={m.text} mine={mine} />
                      <div
                        className={`mt-1 flex flex-wrap items-center gap-2 text-[11px] text-slate-400 ${
                          mine ? "justify-end" : "justify-start"
                        }`}
                      >
                        <span>{formatTime(m.time)}</span>
                        {!mine && (
                          <span
                            className={`rounded-full px-2 py-0.5 font-medium ${
                              m.verified ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-600"
                            }`}
                          >
                            {m.verified ? "Signature verified" : "Unverified"}
                          </span>
                        )}
                        {m.offline && (
                          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-slate-500">Received while offline</span>
                        )}
                        {!mine &&
                          m.msgId &&
                          (reported[m.msgId] ? (
                            <span className="rounded-full bg-slate-100 px-2 py-0.5 text-slate-500">Reported</span>
                          ) : (
                            <button
                              onClick={() => setReportTarget(m)}
                              className="rounded-full px-2 py-0.5 font-medium text-slate-400 transition hover:bg-red-50 hover:text-red-600"
                            >
                              Report
                            </button>
                          ))}
                      </div>
                    </div>
                  </div>
                );
              })}
              <div ref={bottomRef} />
            </div>

            <form onSubmit={onSend} className="flex items-center gap-3 border-t border-slate-200 bg-white px-5 py-3">
              <input
                type="text"
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                placeholder="Type an encrypted message..."
                className="flex-1 rounded-full border border-slate-300 bg-slate-50 px-4 py-2.5 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-500 focus:bg-white focus:ring-4 focus:ring-indigo-100"
              />
              <button
                type="submit"
                disabled={!messageText.trim()}
                className="rounded-full bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300"
              >
                Send
              </button>
            </form>
          </>
        )}
      </section>

      {reportTarget && (
        <ReportDialog target={reportTarget} onClose={() => setReportTarget(null)} onSubmit={onReport} />
      )}
    </div>
  );
}