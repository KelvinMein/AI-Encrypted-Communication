import { useEffect, useState } from "react";
import { RULES, TERMS_VERSION } from "../utils/rules";

const API = "http://127.0.0.1:8000";
const MIN_LENGTH = 8;
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,20}$/;

const FEATURES = [
  { icon: "🔐", title: "End-to-end encrypted", text: "Messages are encrypted in your browser. The server never sees them." },
  { icon: "✍️", title: "Signed and verified", text: "Every message is signed, so you know who really sent it." },
  { icon: "🛡️", title: "AI threat monitoring", text: "Suspicious activity is flagged to administrators in real time." },
];

const TITLES = {
  login: ["Welcome back", "Log in to continue to your conversations."],
  register: ["Create your account", "Choose a username. Others see it, not your email."],
  forgot: ["Forgot your password?", "Enter your email and we will send you a link to choose a new one."],
  reset: ["Choose a new password", "Pick a password you have not used before."],
};

const INPUT =
  "w-full rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 disabled:bg-slate-50";

function Spinner() {
  return (
    <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
  );
}

async function post(path, body) {
  try {
    const res = await fetch(`${API}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    let data = {};
    try {
      data = await res.json();
    } catch {
      data = {};
    }
    return { ok: res.ok, status: res.status, data };
  } catch {
    return { ok: false, status: 0, data: { detail: "Could not reach the server." } };
  }
}

function messageFrom(data, fallback) {
  return typeof data?.detail === "string" ? data.detail : fallback;
}

export default function AuthScreen({ onRegister, onLogin, registerResult, loginResult, keyStatus }) {
  const [mode, setMode] = useState("login"); // login | register | forgot | reset
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [agree, setAgree] = useState(false);
  const [showRules, setShowRules] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);
  const [resetToken, setResetToken] = useState("");

  // A reset link looks like http://localhost:5173/?reset=TOKEN
  useEffect(() => {
    const t = new URLSearchParams(window.location.search).get("reset");
    if (t) {
      setResetToken(t);
      setMode("reset");
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  function go(next, message = "") {
    setMode(next);
    setPassword("");
    setConfirm("");
    setUsername("");
    setAgree(false);
    setError("");
    setNotice(message);
    setSent(false);
    setShowPassword(false);
  }

  async function submit(e) {
    e.preventDefault();
    if (busy) return;
    setError("");
    setNotice("");

    if (mode === "register") {
      if (!USERNAME_RE.test(username.trim()))
        return setError("Username must be 3 to 20 characters: letters, numbers, dots, dashes or underscores.");
      if (password.length < MIN_LENGTH) return setError(`Use at least ${MIN_LENGTH} characters for your password.`);
      if (!agree) return setError("You must agree to the rules to create an account.");
    }
    if (mode === "reset") {
      if (password.length < MIN_LENGTH) return setError(`Use at least ${MIN_LENGTH} characters.`);
      if (password !== confirm) return setError("The two passwords do not match.");
    }

    setBusy(true);
    try {
      if (mode === "login") {
        await onLogin(email, password);
      } else if (mode === "register") {
        const ok = await onRegister(email, password, username.trim(), agree);
        if (ok) go("login", `Account created. Log in with ${email} to continue.`);
      } else if (mode === "forgot") {
        const r = await post("/forgot-password", { email });
        if (r.ok) setSent(true);
        else setError(messageFrom(r.data, "Something went wrong. Please try again."));
      } else {
        const r = await post("/reset-password", { token: resetToken, new_password: password });
        if (r.ok) {
          setResetToken("");
          go("login", "Password updated. Log in with your new password.");
        } else {
          setError(messageFrom(r.data, "This reset link is invalid or has expired."));
        }
      }
    } finally {
      setBusy(false);
    }
  }

  const [title, subtitle] = TITLES[mode];
  const parentMessage = mode === "login" ? loginResult : mode === "register" ? registerResult : "";
  const parentIsError = /error|failed|network/i.test(parentMessage || "");
  const label = { login: "Log in", register: "Create account", forgot: "Send reset link", reset: "Update password" }[mode];
  const busyLabel = { login: "Logging in...", register: "Creating account...", forgot: "Sending...", reset: "Updating..." }[mode];
  const registerBlocked = mode === "register" && !agree;

  return (
    <div className="flex min-h-screen flex-col bg-white lg:flex-row">
      {/* Left: branding panel */}
      <div className="flex flex-1 flex-col justify-between bg-gradient-to-br from-indigo-700 via-indigo-600 to-sky-500 p-8 text-white lg:p-14">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/20 text-xl backdrop-blur">🔒</div>
          <span className="text-lg font-semibold tracking-tight">Secure Messenger</span>
        </div>

        <div className="my-10 max-w-md lg:my-0">
          <h1 className="text-3xl font-bold leading-tight lg:text-4xl">
            Private conversations,
            <br />
            protected by design.
          </h1>
          <p className="mt-4 text-indigo-100">A full-stack encrypted messaging system with live threat detection.</p>
          <ul className="mt-8 space-y-5">
            {FEATURES.map((f) => (
              <li key={f.title} className="flex gap-4">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-white/15 text-lg">{f.icon}</span>
                <div>
                  <p className="font-semibold">{f.title}</p>
                  <p className="text-sm text-indigo-100">{f.text}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>

        <p className="hidden text-xs text-indigo-200 lg:block">AI-Powered Encrypted Communication System</p>
      </div>

      {/* Right: form */}
      <div className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <h2 className="text-2xl font-bold text-slate-900">{title}</h2>
          <p className="mt-1 text-sm text-slate-500">{subtitle}</p>

          {(mode === "login" || mode === "register") && (
            <div className="mt-6 grid grid-cols-2 rounded-xl bg-slate-100 p-1 text-sm font-medium">
              <button
                type="button"
                onClick={() => go("login")}
                className={`rounded-lg py-2 transition ${mode === "login" ? "bg-white text-indigo-600 shadow-sm" : "text-slate-500 hover:text-slate-700"}`}
              >
                Log in
              </button>
              <button
                type="button"
                onClick={() => go("register")}
                className={`rounded-lg py-2 transition ${mode === "register" ? "bg-white text-indigo-600 shadow-sm" : "text-slate-500 hover:text-slate-700"}`}
              >
                Create account
              </button>
            </div>
          )}

          {mode === "forgot" && sent ? (
            <div className="mt-6">
              <div className="rounded-xl bg-emerald-50 px-4 py-4 text-sm text-emerald-800">
                <p className="font-semibold">Check your email</p>
                <p className="mt-1">
                  If an account exists for <span className="font-medium">{email}</span>, a reset link is on its way. It
                  works once and expires in 15 minutes.
                </p>
              </div>
              <button
                type="button"
                onClick={() => go("login")}
                className="mt-4 w-full rounded-xl border border-slate-300 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-50"
              >
                Back to log in
              </button>
            </div>
          ) : (
            <form onSubmit={submit} className="mt-6 space-y-4">
              {mode === "register" && (
                <div>
                  <label className="mb-1.5 block text-sm font-medium text-slate-700">Username</label>
                  <input
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    disabled={busy}
                    maxLength={20}
                    autoComplete="off"
                    placeholder="e.g. jane_d"
                    className={INPUT}
                  />
                  <p className="mt-1.5 text-xs text-slate-400">
                    3 to 20 characters. This is the name other people see. Do not use your email address.
                  </p>
                </div>
              )}

              {mode !== "reset" && (
                <div>
                  <label className="mb-1.5 block text-sm font-medium text-slate-700">Email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    disabled={busy}
                    placeholder="you@example.com"
                    className={INPUT}
                  />
                  {mode === "register" && <p className="mt-1.5 text-xs text-slate-400">Private. Used only to log in and recover your account.</p>}
                </div>
              )}

              {mode !== "forgot" && (
                <div>
                  <label className="mb-1.5 block text-sm font-medium text-slate-700">
                    {mode === "reset" ? "New password" : "Password"}
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      disabled={busy}
                      placeholder={mode === "login" ? "Enter your password" : "At least 8 characters"}
                      className={`${INPUT} pr-16`}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((s) => !s)}
                      className="absolute inset-y-0 right-3 text-xs font-medium text-slate-500 hover:text-indigo-600"
                    >
                      {showPassword ? "Hide" : "Show"}
                    </button>
                  </div>
                  {(mode === "reset" || mode === "register") && (
                    <p className={`mt-1.5 text-xs ${password.length >= MIN_LENGTH ? "text-emerald-600" : "text-slate-400"}`}>
                      {password.length >= MIN_LENGTH ? "Long enough" : `At least ${MIN_LENGTH} characters`}
                    </p>
                  )}
                  {mode === "login" && (
                    <div className="mt-2 text-right">
                      <button
                        type="button"
                        onClick={() => go("forgot")}
                        className="text-xs font-medium text-indigo-600 hover:text-indigo-800"
                      >
                        Forgot password?
                      </button>
                    </div>
                  )}
                </div>
              )}

              {mode === "reset" && (
                <div>
                  <label className="mb-1.5 block text-sm font-medium text-slate-700">Confirm new password</label>
                  <input
                    type={showPassword ? "text" : "password"}
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    required
                    disabled={busy}
                    placeholder="Type it again"
                    className={INPUT}
                  />
                </div>
              )}

              {mode === "register" && (
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                  <input
                    type="checkbox"
                    checked={agree}
                    onChange={(e) => setAgree(e.target.checked)}
                    className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600"
                  />
                  <span>
                    I have read and agree to the{" "}
                    <button
                      type="button"
                      onClick={() => setShowRules(true)}
                      className="font-medium text-indigo-600 underline hover:text-indigo-800"
                    >
                      rules
                    </button>
                    .
                  </span>
                </label>
              )}

              <button
                type="submit"
                disabled={busy || registerBlocked}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 py-2.5 text-sm font-semibold text-white shadow-lg shadow-indigo-200 transition hover:bg-indigo-700 active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busy && <Spinner />}
                {busy ? busyLabel : label}
              </button>

              {(mode === "forgot" || mode === "reset") && (
                <button
                  type="button"
                  onClick={() => go("login")}
                  className="w-full text-center text-sm font-medium text-slate-500 hover:text-indigo-600"
                >
                  Back to log in
                </button>
              )}
            </form>
          )}

          {busy && mode === "login" && keyStatus && (
            <p className="mt-3 text-center text-xs text-slate-500">{keyStatus}</p>
          )}

          {error ? (
            <div className="mt-4 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
          ) : notice ? (
            <div className="mt-4 rounded-xl bg-emerald-50 px-4 py-3 text-sm text-emerald-700">{notice}</div>
          ) : (
            parentMessage &&
            !busy && (
              <div
                className={`mt-4 rounded-xl px-4 py-3 text-sm ${
                  parentIsError ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"
                }`}
              >
                {parentMessage}
              </div>
            )
          )}

          <p className="mt-8 text-center text-xs text-slate-400">
            Your messages are encrypted before they leave this device.
          </p>
        </div>
      </div>

      {/* Rules */}
      {showRules && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 px-4">
          <div className="flex max-h-[85vh] w-full max-w-lg flex-col rounded-2xl bg-white shadow-2xl">
            <div className="border-b border-slate-200 px-6 py-4">
              <h3 className="text-lg font-bold text-slate-900">Rules</h3>
              <p className="text-xs text-slate-500">Version {TERMS_VERSION}. You must agree to these to create an account.</p>
            </div>
            <ol className="flex-1 space-y-3 overflow-y-auto px-6 py-4 text-sm text-slate-700">
              {RULES.map((r, i) => (
                <li key={r.title}>
                  <p className="font-semibold text-slate-900">
                    {i + 1}. {r.title}
                  </p>
                  <p className="text-slate-600">{r.text}</p>
                </li>
              ))}
            </ol>
            <div className="flex gap-3 border-t border-slate-200 px-6 py-4">
              <button
                type="button"
                onClick={() => setShowRules(false)}
                className="flex-1 rounded-xl border border-slate-300 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-50"
              >
                Close
              </button>
              <button
                type="button"
                onClick={() => {
                  setAgree(true);
                  setShowRules(false);
                }}
                className="flex-1 rounded-xl bg-indigo-600 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-700"
              >
                I agree
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}