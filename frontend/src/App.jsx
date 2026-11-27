import { useState, useRef, useEffect } from "react";
import AuthScreen from "./components/AuthScreen";
import Chat, { Avatar } from "./components/Chat";
import AlertsPanel from "./components/AlertsPanel";
import ReportsPanel from "./components/ReportsPanel";
import UsersPanel from "./components/UsersPanel";
import NotificationBell from "./components/NotificationBell";
import Guardian from "./components/Guardian";
import SecurityCentre from "./components/SecurityCentre";
import { assess } from "./utils/guardian";

const API = "http://127.0.0.1:8000";
const WS = "ws://127.0.0.1:8000";
const MAX_MESSAGE_AGE_MS = 60 * 1000; // live messages older than 60 seconds are rejected

// ---- Persistent key storage (IndexedDB), one entry per login email ----
const DB_NAME = "secure-chat-keys";
const STORE = "keys";

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function loadStoredKeys(email) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, "readonly").objectStore(STORE).get(email);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function saveStoredKeys(email, value) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, "readwrite").objectStore(STORE).put(value, email);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

// A random ID kept in this browser, so a login from a new browser can be recognised as a new device
function getDeviceId() {
  try {
    let id = localStorage.getItem("device_id");
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem("device_id", id);
    }
    return id;
  } catch {
    return null;
  }
}

function App() {
  const [regResult, setRegResult] = useState("");
  const [loginResult, setLoginResult] = useState("");
  const [token, setToken] = useState("");
  const [keyStatus, setKeyStatus] = useState("");
  const [myFingerprint, setMyFingerprint] = useState("");
  const [myUsername, setMyUsername] = useState("");

  // "recipientEmail" and the chat "peer" fields now hold usernames, not emails
  const [users, setUsers] = useState([]);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [recipientFingerprint, setRecipientFingerprint] = useState("");
  const [messageText, setMessageText] = useState("");
  const [chatLog, setChatLog] = useState([]);
  const [unread, setUnread] = useState({});
  const [reported, setReported] = useState({});

  const [view, setView] = useState("chat");
  const [isAdmin, setIsAdmin] = useState(false);
  const [flags, setFlags] = useState([]);
  const [flagsLoaded, setFlagsLoaded] = useState(false);
  const [flagsError, setFlagsError] = useState("");
  const [showReviewed, setShowReviewed] = useState(false);
  const [reports, setReports] = useState([]);
  const [reportsError, setReportsError] = useState("");
  const [adminUsers, setAdminUsers] = useState([]);
  const [adminUsersError, setAdminUsersError] = useState("");

  const [wsStatus, setWsStatus] = useState("connecting");
  const [guardianOpen, setGuardianOpen] = useState(false);
  const [secAlert, setSecAlert] = useState(null);

  const keyPairRef = useRef(null);
  const signingKeyPairRef = useRef(null);
  const sharedKeysRef = useRef({});
  const verifyKeysRef = useRef({});
  const seenIdsRef = useRef(new Set());   // message IDs already accepted (replay protection)
  const shownIdsRef = useRef(new Set());  // message IDs already on screen (stops duplicates)
  const lastSentRef = useRef(null);
  const wsRef = useRef(null);
  const myEmailRef = useRef("");          // login email (private), also the key-storage name
  const myUsernameRef = useRef("");       // public name
  const tokenRef = useRef("");
  const recipientRef = useRef("");
  const viewRef = useRef("chat");

  function changeView(next) {
    setView(next);
    viewRef.current = next;
  }

  function markUnread(from) {
    const viewing = viewRef.current === "chat" && recipientRef.current === from;
    if (!viewing) {
      setUnread((prev) => ({ ...prev, [from]: (prev[from] || 0) + 1 }));
    }
  }

  const authHeader = () => ({ Authorization: `Bearer ${tokenRef.current}` });

  async function apiPost(path, body) {
    try {
      const res = await fetch(`${API}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify(body || {}),
      });
      let data = {};
      try {
        data = await res.json();
      } catch {
        data = {};
      }
      return { ok: res.ok, message: typeof data.detail === "string" ? data.detail : data.message || "" };
    } catch {
      return { ok: false, message: "Could not reach the server." };
    }
  }

  // ---- Administrator data ----
  async function loadFlags() {
    try {
      const response = await fetch(`${API}/flags?limit=100`, { headers: authHeader(), cache: "no-store" });
      if (!response.ok) {
        setFlagsError(response.status === 403 ? "Administrator access required." : "Could not load flags.");
        return;
      }
      setFlagsError("");
      setFlags(await response.json());
      setFlagsLoaded(true);
    } catch (err) {
      setFlagsError("Could not reach the server.");
    }
  }

  async function loadReports() {
    try {
      const response = await fetch(`${API}/admin/reports?status=all`, { headers: authHeader(), cache: "no-store" });
      if (!response.ok) {
        setReportsError("Could not load reports.");
        return;
      }
      setReportsError("");
      setReports(await response.json());
    } catch (err) {
      setReportsError("Could not reach the server.");
    }
  }

  async function loadAdminUsers() {
    try {
      const response = await fetch(`${API}/admin/users`, { headers: authHeader(), cache: "no-store" });
      if (!response.ok) {
        setAdminUsersError("Could not load people.");
        return;
      }
      setAdminUsersError("");
      setAdminUsers(await response.json());
    } catch (err) {
      setAdminUsersError("Could not reach the server.");
    }
  }

  async function markReviewed(flagId) {
    await apiPost(`/flags/${flagId}/review`);
    loadFlags();
  }

  async function dismissReport(id, note) {
    const res = await apiPost(`/admin/reports/${id}/dismiss`, { note });
    await loadReports();
    return res;
  }

  async function deactivateUser(userId, reason) {
    const res = await apiPost(`/admin/users/${userId}/deactivate`, { reason });
    await Promise.all([loadReports(), loadAdminUsers()]);
    return res;
  }

  async function reactivateUser(userId) {
    const res = await apiPost(`/admin/users/${userId}/reactivate`);
    await loadAdminUsers();
    return res;
  }

  async function changeRole(userId, role) {
    const res = await apiPost(`/admin/users/${userId}/role`, { role });
    await loadAdminUsers();
    return res;
  }

  useEffect(() => {
    if (!isAdmin || !token) return;
    loadFlags();
    loadReports();
    const timer = setInterval(() => {
      loadFlags();
      loadReports();
    }, 5000);
    return () => clearInterval(timer);
  }, [isAdmin, token]);

  useEffect(() => {
    if (isAdmin && token && view === "users") loadAdminUsers();
  }, [view, isAdmin, token]);

  useEffect(() => {
    const total = Object.values(unread).reduce((a, b) => a + b, 0);
    document.title = total > 0 ? `(${total}) Secure Messenger` : "Secure Messenger";
  }, [unread]);

  useEffect(() => {
    if (view === "chat" && recipientEmail) {
      setUnread((prev) => (prev[recipientEmail] ? { ...prev, [recipientEmail]: 0 } : prev));
    }
  }, [view, recipientEmail]);

    // Polls for new-device alerts, and returns to the login screen if this session was ended elsewhere
  useEffect(() => {
    if (!token) return;
    let stop = false;
    async function check() {
      try {
        const res = await fetch(`${API}/security/notifications`, { headers: authHeader(), cache: "no-store" });
        if (res.status === 401) {
          window.location.reload();
          return;
        }
        if (!res.ok || stop) return;
        const data = await res.json();
        setSecAlert(data.unread > 0 || data.unconfirmed > 0 ? data : null);
      } catch {
        /* ignore */
      }
    }
    check();
    const t = setInterval(check, 10000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [token]);

  async function handleRegister(email, password, username, acceptTerms) {
    setRegResult("Creating account...");
    try {
      const response = await fetch(`${API}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, username, accept_terms: acceptTerms }),
      });
      const data = await response.json();
      if (response.ok) {
        setRegResult("Account created.");
        return true;
      }
      setRegResult(
        `Error: ${typeof data.detail === "string" ? data.detail : "Please check the details you entered."}`
      );
      return false;
    } catch (err) {
      setRegResult(`Network error: ${err.message}`);
      return false;
    }
  }

  async function deriveSharedKey(theirPublicKeyBase64) {
    const raw = Uint8Array.from(atob(theirPublicKeyBase64), (c) => c.charCodeAt(0));
    const theirKey = await crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
    return await crypto.subtle.deriveKey(
      { name: "ECDH", public: theirKey },
      keyPairRef.current.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function importVerifyKey(signingKeyBase64) {
    const raw = Uint8Array.from(atob(signingKeyBase64), (c) => c.charCodeAt(0));
    return await crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  }

  async function computeFingerprint(publicKeyBase64, signingKeyBase64) {
    const combined = publicKeyBase64 + signingKeyBase64;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(combined));
    const bytes = Array.from(new Uint8Array(digest)).slice(0, 8);
    return bytes.map((b) => b.toString(16).padStart(2, "0")).join(":");
  }

  // The signature covers the message ID, timestamp, nonce and ciphertext together.
  function buildSignedBytes(msgId, timestamp, nonceBase64, ciphertextBase64) {
    return new TextEncoder().encode(`${msgId}|${timestamp}|${nonceBase64}|${ciphertextBase64}`);
  }

  // Downloads this user's own ciphertext history and decrypts it in the browser.
  async function loadHistory(jwtToken) {
    try {
      const headers = { Authorization: `Bearer ${jwtToken}` };
      const [msgRes, usersRes] = await Promise.all([
        fetch(`${API}/messages`, { headers, cache: "no-store" }),
        fetch(`${API}/users`, { headers, cache: "no-store" }),
      ]);
      if (!msgRes.ok || !usersRes.ok) return;
      const rows = await msgRes.json();
      const everyone = await usersRes.json();

      const peers = {};
      const items = [];
      const unreadCounts = {};
      const unreadable = {};

      for (const r of rows) {
        if (r.msg_id && shownIdsRef.current.has(r.msg_id)) continue;
        if (r.msg_id) {
          shownIdsRef.current.add(r.msg_id);
          seenIdsRef.current.add(r.msg_id);
        }

        const mine = r.from === myUsernameRef.current;
        const peerName = mine ? r.to : r.from;
        if (!peerName) continue;

        if (!(peerName in peers)) {
          const match = everyone.find((u) => u.username === peerName);
          if (match && match.public_key && match.signing_key) {
            peers[peerName] = {
              sharedKey: await deriveSharedKey(match.public_key),
              verifyKey: await importVerifyKey(match.signing_key),
            };
          } else {
            peers[peerName] = null;
          }
        }
        const peer = peers[peerName];
        if (!peer) {
          unreadable[peerName] = (unreadable[peerName] || 0) + 1;
          continue;
        }

        try {
          const nonce = Uint8Array.from(atob(r.nonce), (c) => c.charCodeAt(0));
          const ciphertextBytes = Uint8Array.from(atob(r.ciphertext), (c) => c.charCodeAt(0));
          const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, peer.sharedKey, ciphertextBytes);
          const text = new TextDecoder().decode(decrypted);

          let verified = true;
          if (!mine) {
            try {
              const sigBytes = Uint8Array.from(atob(r.signature), (c) => c.charCodeAt(0));
              verified = await crypto.subtle.verify(
                { name: "ECDSA", hash: "SHA-256" },
                peer.verifyKey,
                sigBytes,
                buildSignedBytes(r.msg_id, r.timestamp, r.nonce, r.ciphertext)
              );
            } catch (err) {
              verified = false;
            }
          }

          const offline = !mine && r.delivered === false;
          if (offline) unreadCounts[peerName] = (unreadCounts[peerName] || 0) + 1;

          items.push({
            peer: peerName,
            from: mine ? "me" : peerName,
            text,
            verified,
            offline,
            time: r.timestamp,
            msgId: r.msg_id,
          });
        } catch (err) {
          unreadable[peerName] = (unreadable[peerName] || 0) + 1;
        }
      }

      const notes = Object.entries(unreadable).map(([peerName, n]) => ({
        peer: peerName,
        from: peerName,
        system: true,
        text: `${n} earlier message${n > 1 ? "s" : ""} can't be shown, because the encryption keys changed since ${
          n > 1 ? "they were" : "it was"
        } sent`,
        time: 0,
      }));

      setChatLog((prev) => [...notes, ...items, ...prev]);
      if (Object.keys(unreadCounts).length > 0) {
        setUnread((prev) => {
          const next = { ...prev };
          for (const [k, v] of Object.entries(unreadCounts)) next[k] = (next[k] || 0) + v;
          return next;
        });
      }
    } catch (err) {
      // History is a convenience: if it fails, chatting still works
    }
  }

  async function generateAndUploadKeys(jwtToken) {
    let stored = await loadStoredKeys(myEmailRef.current);

    if (stored) {
      setKeyStatus("Loading your saved keys...");
    } else {
      setKeyStatus("Generating keys for the first time...");
      const ecdhPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
      const signingPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
      stored = { ecdhPair, signingPair };
      await saveStoredKeys(myEmailRef.current, stored);
    }

    keyPairRef.current = stored.ecdhPair;
    signingKeyPairRef.current = stored.signingPair;

    const rawPublicKey = await crypto.subtle.exportKey("raw", stored.ecdhPair.publicKey);
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(rawPublicKey)));
    const rawSigningPublicKey = await crypto.subtle.exportKey("raw", stored.signingPair.publicKey);
    const signingPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(rawSigningPublicKey)));

    setMyFingerprint(await computeFingerprint(publicKeyBase64, signingPublicKeyBase64));

    setKeyStatus("Uploading public keys...");
    const response = await fetch(`${API}/upload-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${jwtToken}` },
      body: JSON.stringify({ public_key: publicKeyBase64, signing_key: signingPublicKeyBase64 }),
    });

    if (response.ok) {
      setKeyStatus("Restoring your conversations...");
      await loadHistory(jwtToken);
      setKeyStatus("Encryption and signing keys ready.");
      loadUsers(jwtToken);
      connectWebSocket(jwtToken);
    } else {
      const data = await response.json();
      setKeyStatus(`Key upload failed: ${typeof data.detail === "string" ? data.detail : "please try again"}`);
    }
  }

  async function loadUsers(jwtToken) {
    const response = await fetch(`${API}/users`, { headers: { Authorization: `Bearer ${jwtToken}` }, cache: "no-store" });
    const data = await response.json();
    // Hide yourself and the simulator's test accounts from the contacts list
    setUsers(data.filter((u) => u.username !== myUsernameRef.current && !u.username.startsWith("sim.")));
  }

  // Fetches a person's current keys (looked up by username) and prepares the shared AES key and verify key
  async function getPeerKeys(username) {
    const response = await fetch(`${API}/users`, { headers: authHeader(), cache: "no-store" });
    const data = await response.json();
    const match = data.find((u) => u.username === username);
    if (!match || !match.public_key || !match.signing_key) return null;

    const sharedKey = await deriveSharedKey(match.public_key);
    const verifyKey = await importVerifyKey(match.signing_key);
    sharedKeysRef.current[username] = sharedKey;
    verifyKeysRef.current[username] = verifyKey;
    return { sharedKey, verifyKey, publicKey: match.public_key, signingKey: match.signing_key };
  }

  function connectWebSocket(jwtToken) {
    setWsStatus("connecting");
    const ws = new WebSocket(`${WS}/ws/${jwtToken}`);

    ws.onopen = () => setWsStatus("open");
    ws.onclose = () => setWsStatus("closed");
    ws.onerror = () => setWsStatus("closed");

    ws.onmessage = async (event) => {
      const data = JSON.parse(event.data);

      if (data.offline && data.msg_id && shownIdsRef.current.has(data.msg_id)) return;

      const peer = await getPeerKeys(data.from);
      if (!peer) return;

      const nonce = Uint8Array.from(atob(data.nonce), (c) => c.charCodeAt(0));
      const ciphertextBytes = Uint8Array.from(atob(data.ciphertext), (c) => c.charCodeAt(0));

      let signatureValid = false;
      try {
        if (data.signature && data.msg_id && data.timestamp) {
          const signatureBytes = Uint8Array.from(atob(data.signature), (c) => c.charCodeAt(0));
          const signedBytes = buildSignedBytes(data.msg_id, data.timestamp, data.nonce, data.ciphertext);
          signatureValid = await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" }, peer.verifyKey, signatureBytes, signedBytes
          );
        }
      } catch (err) {
        signatureValid = false;
      }

      if (signatureValid) {
        if (!data.offline) {
          const age = Math.abs(Date.now() - data.timestamp);
          if (age > MAX_MESSAGE_AGE_MS) {
            setChatLog((prev) => [
              ...prev,
              { peer: data.from, from: data.from, text: "Rejected: message expired", rejected: true, time: Date.now() },
            ]);
            return;
          }
        }
        if (seenIdsRef.current.has(data.msg_id)) {
          setChatLog((prev) => [
            ...prev,
            { peer: data.from, from: data.from, text: "Rejected: replayed message", rejected: true, time: Date.now() },
          ]);
          return;
        }
        seenIdsRef.current.add(data.msg_id);
      }

      try {
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, peer.sharedKey, ciphertextBytes);
        const text = new TextDecoder().decode(decrypted);
        if (data.msg_id) shownIdsRef.current.add(data.msg_id);
        setChatLog((prev) => [
          ...prev,
          {
            peer: data.from,
            from: data.from,
            text,
            verified: signatureValid,
            offline: !!data.offline,
            time: data.timestamp,
            msgId: data.msg_id,
          },
        ]);
        markUnread(data.from);
      } catch (err) {
        setChatLog((prev) => [
          ...prev,
          { peer: data.from, from: data.from, text: "Could not decrypt message", rejected: true, time: Date.now() },
        ]);
      }
    };

    wsRef.current = ws;
  }

  async function handleLogin(email, password) {
    setLoginResult("Logging in...");
    try {
      const response = await fetch(`${API}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password, device_id: getDeviceId() }),
      });
      const data = await response.json();

      if (response.ok) {
        setToken(data.access_token);
        tokenRef.current = data.access_token;
        myEmailRef.current = email;
        myUsernameRef.current = data.username;
        setMyUsername(data.username);
        setIsAdmin(data.role === "admin");
        setLoginResult("Login successful.");
        await generateAndUploadKeys(data.access_token);
      } else {
        setLoginResult(`Error: ${typeof data.detail === "string" ? data.detail : "Could not log in."}`);
      }
    } catch (err) {
      setLoginResult(`Network error: ${err.message}`);
    }
  }

  async function handleSelectRecipient(username) {
    setRecipientEmail(username);
    recipientRef.current = username;
    setUnread((prev) => ({ ...prev, [username]: 0 }));
    setRecipientFingerprint("");

    const peer = await getPeerKeys(username);
    if (peer) {
      setRecipientFingerprint(await computeFingerprint(peer.publicKey, peer.signingKey));
    }
  }

  async function handleSendMessage(e) {
    e.preventDefault();
    if (!recipientEmail || !messageText.trim() || !wsRef.current) return;

    const sharedKey = sharedKeysRef.current[recipientEmail];
    if (!sharedKey) return;

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(messageText);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, sharedKey, plaintext);
    const ciphertextBytes = new Uint8Array(ciphertext);

    const nonceBase64 = btoa(String.fromCharCode(...nonce));
    const ciphertextBase64 = btoa(String.fromCharCode(...ciphertextBytes));

    const msgId = crypto.randomUUID();
    const timestamp = Date.now();

    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      signingKeyPairRef.current.privateKey,
      buildSignedBytes(msgId, timestamp, nonceBase64, ciphertextBase64)
    );
    const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

    const payload = {
      to: recipientEmail,
      ciphertext: ciphertextBase64,
      nonce: nonceBase64,
      signature: signatureBase64,
      msg_id: msgId,
      timestamp: timestamp,
    };

    wsRef.current.send(JSON.stringify(payload));
    lastSentRef.current = payload;
    shownIdsRef.current.add(msgId);

    setChatLog((prev) => [
      ...prev,
      { peer: recipientEmail, from: "me", text: messageText, verified: true, time: timestamp, msgId },
    ]);
    setMessageText("");
  }

  function handleReplayLast() {
    if (!lastSentRef.current || !wsRef.current) return;
    wsRef.current.send(JSON.stringify(lastSentRef.current));
    setChatLog((prev) => [
      ...prev,
      {
        peer: lastSentRef.current.to,
        from: "me",
        text: "You re-sent your last message to test replay protection",
        system: true,
        time: Date.now(),
      },
    ]);
  }

  // Sends a report. The message text is included only if the reporter chose to share it.
  async function submitReport(target, { reason, details, includeText }) {
    const res = await apiPost("/reports", {
      msg_id: target.msgId,
      reason,
      details: details || null,
      evidence_text: includeText ? target.text : null,
    });
    if (res.ok) setReported((prev) => ({ ...prev, [target.msgId]: true }));
    return res;
  }

    async function handleLogout() {
    await apiPost("/logout"); // ends this session on the server too
    window.location.reload();
  }

  // ---------- Logged-out view ----------
  if (!token) {
    return (
      <AuthScreen
        onRegister={handleRegister}
        onLogin={handleLogin}
        registerResult={regResult}
        loginResult={loginResult}
        keyStatus={keyStatus}
      />
    );
  }

  // ---------- Logged-in view ----------
  const unreviewedCount = flags.filter((f) => !f.reviewed).length;
  const openReports = reports.filter((r) => r.status === "open").length;
  const conversation = chatLog.filter((m) => m.peer === recipientEmail);
  const keysReady = keyStatus.startsWith("Encryption and signing keys ready");
  const totalUnread = Object.values(unread).reduce((a, b) => a + b, 0);

  const guardian = assess({ keysReady, wsStatus, messages: chatLog, recipientEmail, isAdmin, flags });
  const guardianDot = { good: "bg-emerald-500", notice: "bg-amber-400", warning: "bg-red-500" }[guardian.level];

  const tab = (name, active) =>
    `flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
      active ? "bg-indigo-50 text-indigo-700" : "text-slate-500 hover:text-slate-800"
    }`;

  return (
    <div className="flex h-screen flex-col bg-slate-50">
      <header className="flex items-center justify-between gap-4 border-b border-slate-200 bg-white px-5 py-3">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-lg text-white">🔒</div>
            <span className="hidden text-base font-bold text-slate-900 sm:block">Secure Messenger</span>
          </div>

          <nav className="flex gap-1">
            <button onClick={() => changeView("chat")} className={tab("chat", view === "chat")}>
              Messages
              {totalUnread > 0 && (
                <span className="rounded-full bg-indigo-600 px-2 py-0.5 text-[11px] font-semibold text-white">{totalUnread}</span>
              )}
            </button>
                        <button onClick={() => changeView("security")} className={tab("security", view === "security")}>
              Security centre
              {secAlert && <span className="h-2 w-2 rounded-full bg-red-600"></span>}
            </button>
            {isAdmin && (
              <>
                <button onClick={() => changeView("alerts")} className={tab("alerts", view === "alerts")}>
                  Security alerts
                  {unreviewedCount > 0 && (
                    <span className="rounded-full bg-red-600 px-2 py-0.5 text-[11px] font-semibold text-white">{unreviewedCount}</span>
                  )}
                </button>
                <button onClick={() => changeView("reports")} className={tab("reports", view === "reports")}>
                  Reports
                  {openReports > 0 && (
                    <span className="rounded-full bg-red-600 px-2 py-0.5 text-[11px] font-semibold text-white">{openReports}</span>
                  )}
                </button>
                <button onClick={() => changeView("users")} className={tab("users", view === "users")}>
                  People
                </button>
              </>
            )}
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 text-xs text-slate-500 md:flex">
            <span className={`h-2 w-2 rounded-full ${keysReady ? "bg-emerald-500" : "bg-amber-400"}`}></span>
            {keysReady ? "Keys ready" : keyStatus}
            {myFingerprint && (
              <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">{myFingerprint}</code>
            )}
          </div>

          <button
            onClick={() => setGuardianOpen(true)}
            title="Security Guardian"
            className="flex h-10 items-center gap-2 rounded-full px-3 text-sm font-medium text-slate-600 transition hover:bg-slate-100"
          >
            <span className="text-lg">🛡️</span>
            <span className="hidden lg:inline">Guardian</span>
            <span className={`h-2.5 w-2.5 rounded-full ${guardianDot}`}></span>
          </button>

          {isAdmin && (
            <NotificationBell flags={flags} ready={flagsLoaded} onReview={markReviewed} onViewAll={() => changeView("alerts")} />
          )}

          <div className="flex items-center gap-2">
            <Avatar email={myUsername} size="h-8 w-8 text-xs" />
            <div className="hidden leading-tight sm:block">
              <p className="text-sm font-medium text-slate-800">{myUsername}</p>
              {isAdmin && <p className="text-[11px] font-semibold text-indigo-600">Administrator</p>}
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100"
          >
            Log out
          </button>
        </div>
      </header>
            {secAlert && view !== "security" && (
        <button
          onClick={() => changeView("security")}
          className="w-full border-b border-red-200 bg-red-50 px-5 py-2 text-left text-sm font-medium text-red-800 transition hover:bg-red-100"
        >
          {secAlert.unconfirmed > 0
            ? "A new device signed in to your account. Was this you? Review it in Security centre."
            : "You have new security notifications. Open Security centre."}
        </button>
      )}

      <main className="min-h-0 flex-1 overflow-hidden">
                {view === "security" ? (
          <div className="h-full overflow-y-auto">
            <SecurityCentre token={token} />
          </div>
        ) : view === "chat" || !isAdmin ? (
          <Chat
            users={users}
            unread={unread}
            recipientEmail={recipientEmail}
            onSelect={handleSelectRecipient}
            recipientFingerprint={recipientFingerprint}
            messages={conversation}
            messageText={messageText}
            setMessageText={setMessageText}
            onSend={handleSendMessage}
            onReplay={handleReplayLast}
            reported={reported}
            onReport={submitReport}
          />
        ) : (
          <div className="h-full overflow-y-auto">
            {view === "alerts" && (
              <AlertsPanel
                flags={flags}
                error={flagsError}
                showReviewed={showReviewed}
                setShowReviewed={setShowReviewed}
                onReview={markReviewed}
              />
            )}
            {view === "reports" && (
              <ReportsPanel
                reports={reports}
                error={reportsError}
                onDismiss={dismissReport}
                onDeactivate={deactivateUser}
              />
            )}
            {view === "users" && (
              <UsersPanel
                users={adminUsers}
                error={adminUsersError}
                me={myUsername}
                onDeactivate={deactivateUser}
                onReactivate={reactivateUser}
                onRole={changeRole}
              />
            )}
          </div>
        )}
      </main>

      <Guardian
        open={guardianOpen}
        onClose={() => setGuardianOpen(false)}
        assessment={guardian}
        isAdmin={isAdmin}
        onOpenAlerts={() => {
          setGuardianOpen(false);
          changeView("alerts");
        }}
      />
    </div>
  );
}

export default App;