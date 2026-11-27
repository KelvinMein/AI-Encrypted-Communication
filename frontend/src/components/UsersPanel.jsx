export default function UsersPanel({ users, error, me, onDeactivate, onReactivate, onRole }) {
  async function deactivate(u) {
    const reason = window.prompt(`Why are you deactivating ${u.username}? They will be logged out.`);
    if (reason === null) return;
    if (!reason.trim()) return window.alert("A reason is required.");
    const res = await onDeactivate(u.id, reason.trim());
    if (!res.ok) window.alert(res.message || "That did not work.");
  }

  async function role(u) {
    const next = u.role === "admin" ? "user" : "admin";
    if (!window.confirm(`Make ${u.username} ${next === "admin" ? "an administrator" : "an ordinary user"}?`)) return;
    const res = await onRole(u.id, next);
    if (!res.ok) window.alert(res.message || "That did not work.");
  }

  return (
    <div className="mx-auto max-w-5xl p-6">
      <h2 className="text-2xl font-bold text-slate-900">People</h2>
      <p className="text-sm text-slate-500">Everyone with an account. Only administrators can see email addresses.</p>

      {error && <div className="mt-4 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}

      <div className="mt-5 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-5 py-3 font-medium">Username</th>
                <th className="px-5 py-3 font-medium">Email</th>
                <th className="px-5 py-3 font-medium">Role</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Reports</th>
                <th className="px-5 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {users.map((u) => {
                const self = u.username === me;
                return (
                  <tr key={u.id} className={u.is_active ? "" : "bg-slate-50 text-slate-400"}>
                    <td className="px-5 py-3 font-medium text-slate-800">
                      {u.username}
                      {self && <span className="ml-2 text-xs text-indigo-600">(you)</span>}
                    </td>
                    <td className="px-5 py-3">{u.email}</td>
                    <td className="px-5 py-3">
                      <span
                        className={`rounded-full px-2.5 py-1 text-xs font-medium ${
                          u.role === "admin" ? "bg-indigo-100 text-indigo-700" : "bg-slate-100 text-slate-600"
                        }`}
                      >
                        {u.role === "admin" ? "Admin" : "User"}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      {u.is_active ? (
                        <span className="rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-700">Active</span>
                      ) : (
                        <span title={u.deactivated_reason || ""} className="rounded-full bg-red-100 px-2.5 py-1 text-xs font-medium text-red-700">
                          Deactivated
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      {u.total_reports > 0 ? (
                        <span className={u.open_reports > 0 ? "font-semibold text-red-600" : ""}>
                          {u.total_reports} ({u.open_reports} open)
                        </span>
                      ) : (
                        "0"
                      )}
                    </td>
                    <td className="px-5 py-3 text-right">
                      {!self && (
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => role(u)}
                            className="rounded-lg border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-600 transition hover:bg-slate-50"
                          >
                            {u.role === "admin" ? "Make user" : "Make admin"}
                          </button>
                          {u.is_active ? (
                            u.role !== "admin" && (
                              <button
                                onClick={() => deactivate(u)}
                                className="rounded-lg bg-red-600 px-2.5 py-1 text-xs font-semibold text-white transition hover:bg-red-700"
                              >
                                Deactivate
                              </button>
                            )
                          ) : (
                            <button
                              onClick={() => onReactivate(u.id)}
                              className="rounded-lg bg-emerald-600 px-2.5 py-1 text-xs font-semibold text-white transition hover:bg-emerald-700"
                            >
                              Reactivate
                            </button>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}