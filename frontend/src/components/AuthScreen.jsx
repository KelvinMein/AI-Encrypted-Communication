import { useState } from "react";

const FEATURES = [
  { icon: "🔐", title: "End-to-end encrypted", text: "Messages are encrypted in your browser. The server never sees them." },
  { icon: "✍️", title: "Signed and verified", text: "Every message is signed, so you know who really sent it." },
  { icon: "🛡️", title: "AI threat monitoring", text: "Suspicious activity is flagged to administrators in real time." },
];

export default function AuthScreen({
  onRegister,
  onLogin,
  registerResult,
  loginResult,
  keyStatus,
}) {
  const [tab, setTab] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const isLogin = tab === "login";
  const message = isLogin ? loginResult : registerResult;
  const isError = /error|failed|network/i.test(message || "");

  function submit(e) {
    e.preventDefault();
    if (isLogin) onLogin(email, password);
    else onRegister(email, password);
  }

  return (
    <div className="flex min-h-screen flex-col bg-white lg:flex-row">
      {/* Left: branding panel */}
      <div className="flex flex-1 flex-col justify-between bg-gradient-to-br from-indigo-700 via-indigo-600 to-sky-500 p-8 text-white lg:p-14">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/20 text-xl backdrop-blur">
            🔒
          </div>
          <span className="text-lg font-semibold tracking-tight">Secure Messenger</span>
        </div>

        <div className="my-10 max-w-md lg:my-0">
          <h1 className="text-3xl font-bold leading-tight lg:text-4xl">
            Private conversations,
            <br />
            protected by design.
          </h1>
          <p className="mt-4 text-indigo-100">
            A full-stack encrypted messaging system with live threat detection.
          </p>

          <ul className="mt-8 space-y-5">
            {FEATURES.map((f) => (
              <li key={f.title} className="flex gap-4">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-white/15 text-lg">
                  {f.icon}
                </span>
                <div>
                  <p className="font-semibold">{f.title}</p>
                  <p className="text-sm text-indigo-100">{f.text}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>

        <p className="hidden text-xs text-indigo-200 lg:block">
          AI-Powered Encrypted Communication System
        </p>
      </div>

      {/* Right: form */}
      <div className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <h2 className="text-2xl font-bold text-slate-900">
            {isLogin ? "Welcome back" : "Create your account"}
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            {isLogin ? "Log in to continue to your conversations." : "It only takes a moment."}
          </p>

          <div className="mt-6 grid grid-cols-2 rounded-xl bg-slate-100 p-1 text-sm font-medium">
            <button
              type="button"
              onClick={() => setTab("login")}
              className={`rounded-lg py-2 transition ${
                isLogin ? "bg-white text-indigo-600 shadow-sm" : "text-slate-500 hover:text-slate-700"
              }`}
            >
              Log in
            </button>
            <button
              type="button"
              onClick={() => setTab("register")}
              className={`rounded-lg py-2 transition ${
                !isLogin ? "bg-white text-indigo-600 shadow-sm" : "text-slate-500 hover:text-slate-700"
              }`}
            >
              Create account
            </button>
          </div>

          <form onSubmit={submit} className="mt-6 space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                placeholder="you@example.com"
                className="w-full rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="Enter your password"
                  className="w-full rounded-xl border border-slate-300 bg-white px-4 py-2.5 pr-16 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="absolute inset-y-0 right-3 text-xs font-medium text-slate-500 hover:text-indigo-600"
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="w-full rounded-xl bg-indigo-600 py-2.5 text-sm font-semibold text-white shadow-lg shadow-indigo-200 transition hover:bg-indigo-700 active:scale-[0.99]"
            >
              {isLogin ? "Log in" : "Create account"}
            </button>
          </form>

          {message && (
            <div
              className={`mt-4 rounded-xl px-4 py-3 text-sm ${
                isError ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"
              }`}
            >
              {message}
            </div>
          )}
          {isLogin && keyStatus && (
            <p className="mt-3 text-center text-xs text-slate-500">{keyStatus}</p>
          )}

          <p className="mt-8 text-center text-xs text-slate-400">
            Your messages are encrypted before they leave this device.
          </p>
        </div>
      </div>
    </div>
  );
}