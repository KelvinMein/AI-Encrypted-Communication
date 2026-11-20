import { useState, useRef, useEffect } from "react";
import AuthScreen from "./components/AuthScreen";
import Chat, { Avatar } from "./components/Chat";
import AlertsPanel from "./components/AlertsPanel";

const MAX_MESSAGE_AGE_MS = 60 * 1000; // live messages older than 60 seconds are rejected
const ADMIN_EMAILS = ["kelvin@example.com"]; // cosmetic only: the server enforces admin access

// ---- Persistent key storage (IndexedDB), one entry per email ----
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

function App() {
  const [regResult, setRegResult] = useState("");
  const [loginResult, setLoginResult] = useState("");
  const [token, setToken] = useState("");
  const [keyStatus, setKeyStatus] = useState("");
  const [myFingerprint, setMyFingerprint] = useState("");

  const [users, setUsers] = useState([]);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [recipientFingerprint, setRecipientFingerprint] = useState("");
  const [messageText, setMessageText] = useState("");
  const [chatLog, setChatLog] = useState([]);

  const [view, setView] = useState("chat");
  const [isAdmin, setIsAdmin] = useState(false);
  const [flags, setFlags] = useState([]);
  const [flagsError, setFlagsError] = useState("");
  const [showReviewed, setShowReviewed] = useState(false);

  const keyPairRef = useRef(null);
  const signingKeyPairRef = useRef(null);
  const sharedKeysRef = useRef({});
  const verifyKeysRef = useRef({});
  const seenIdsRef = useRef(new Set());
  const lastSentRef = useRef(null);
  const wsRef = useRef(null);
  const myEmailRef = useRef("");
  const tokenRef = useRef("");

  // ---- Admin: load and refresh anomaly flags ----
  async function loadFlags() {
    try {
      const response = await fetch("http://127.0.0.1:8000/flags?limit=100", {
        headers: { Authorization: `Bearer ${tokenRef.current}` },
        cache: "no-store",
      });
      if (!response.ok) {
        setFlagsError(response.status === 403 ? "Administrator access required." : "Could not load flags.");
        return;
      }
      setFlagsError("");
      setFlags(await response.json());
    } catch (err) {
      setFlagsError("Could not reach the server.");
    }
  }

  async function markReviewed(flagId) {
    await fetch(`http://127.0.0.1:8000/flags/${flagId}/review`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tokenRef.current}` },
    });
    loadFlags();
  }

  useEffect(() => {
    if (!isAdmin || !token) return;
    loadFlags();
    const timer = setInterval(loadFlags, 5000);
    return () => clearInterval(timer);
  }, [isAdmin, token]);

  async function handleRegister(email, password) {
    setRegResult("Creating account...");
    try {
      const response = await fetch("http://127.0.0.1:8000/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
      setRegResult(response.ok ? `Account created for ${data.email}. You can log in now.` : `Error: ${data.detail}`);
    } catch (err) {
      setRegResult(`Network error: ${err.message}`);
    }
  }

  async function deriveSharedKey(theirPublicKeyBase64) {
    const raw = Uint8Array.from(atob(theirPublicKeyBase64), (c) => c.charCodeAt(0));
    const theirKey = await crypto.subtle.importKey(
      "raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []
    );
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
    return await crypto.subtle.importKey(
      "raw", raw, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]
    );
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

  async function generateAndUploadKeys(jwtToken) {
    // Reuse this user's saved keys if they exist, otherwise create and save new ones
    let stored = await loadStoredKeys(myEmailRef.current);

    if (stored) {
      setKeyStatus("Loading your saved keys...");
    } else {
      setKeyStatus("Generating keys for the first time...");
      // extractable=false: the private keys can be used but never read out by JavaScript
      const ecdhPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]
      );
      const signingPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]
      );
      stored = { ecdhPair, signingPair };
      await saveStoredKeys(myEmailRef.current, stored);
    }

    keyPairRef.current = stored.ecdhPair;
    signingKeyPairRef.current = stored.signingPair;

    const rawPublicKey = await crypto.subtle.exportKey("raw", stored.ecdhPair.publicKey);
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(rawPublicKey)));
    const rawSigningPublicKey = await crypto.subtle.exportKey("raw", stored.signingPair.publicKey);
    const signingPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(rawSigningPublicKey)));

    const fingerprint = await computeFingerprint(publicKeyBase64, signingPublicKeyBase64);
    setMyFingerprint(fingerprint);

    setKeyStatus("Uploading public keys...");
    const response = await fetch("http://127.0.0.1:8000/upload-key", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${jwtToken}` },
      body: JSON.stringify({ public_key: publicKeyBase64, signing_key: signingPublicKeyBase64 }),
    });

    if (response.ok) {
      setKeyStatus("Encryption and signing keys ready.");
      loadUsers(jwtToken);
      connectWebSocket(jwtToken);
    } else {
      const data = await response.json();
      setKeyStatus(`Key upload failed: ${data.detail}`);
    }
  }

  async function loadUsers(jwtToken) {
    const response = await fetch("http://127.0.0.1:8000/users", {
      headers: { Authorization: `Bearer ${jwtToken}` },
      cache: "no-store",
    });
    const data = await response.json();
    // Hide yourself and the simulator's test accounts from the contacts list
    setUsers(data.filter((u) => u.email !== myEmailRef.current && !u.email.startsWith("sim.")));
  }

  // Fetches a person's current keys and prepares the shared AES key and verify key
  async function getPeerKeys(email) {
    const response = await fetch("http://127.0.0.1:8000/users", {
      headers: { Authorization: `Bearer ${tokenRef.current}` },
      cache: "no-store",
    });
    const data = await response.json();
    const match = data.find((u) => u.email === email);
    if (!match || !match.public_key || !match.signing_key) return null;

    const sharedKey = await deriveSharedKey(match.public_key);
    const verifyKey = await importVerifyKey(match.signing_key);
    sharedKeysRef.current[email] = sharedKey;
    verifyKeysRef.current[email] = verifyKey;
    return { sharedKey, verifyKey, publicKey: match.public_key, signingKey: match.signing_key };
  }

  function connectWebSocket(jwtToken) {
    const ws = new WebSocket(`ws://127.0.0.1:8000/ws/${jwtToken}`);

    ws.onmessage = async (event) => {
      const data = JSON.parse(event.data);

      // Works even if the sender isn't the contact currently selected
      const peer = await getPeerKeys(data.from);
      if (!peer) return;

      const nonce = Uint8Array.from(atob(data.nonce), (c) => c.charCodeAt(0));
      const ciphertextBytes = Uint8Array.from(atob(data.ciphertext), (c) => c.charCodeAt(0));

      // 1. Verify the signature over id + timestamp + nonce + ciphertext
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

      // 2. Replay protection (only after the signature is valid).
      //    Messages delivered from the server's offline store skip the age check,
      //    since they were legitimately sent earlier, but are still checked for duplicates.
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

      // 3. Decrypt and display
      try {
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, peer.sharedKey, ciphertextBytes);
        const text = new TextDecoder().decode(decrypted);
        setChatLog((prev) => [
          ...prev,
          { peer: data.from, from: data.from, text, verified: signatureValid, offline: !!data.offline, time: data.timestamp },
        ]);
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
      const response = await fetch("http://127.0.0.1:8000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();

      if (response.ok) {
        setToken(data.access_token);
        tokenRef.current = data.access_token;
        myEmailRef.current = email;
        setIsAdmin(ADMIN_EMAILS.includes(email));
        setLoginResult("Login successful.");
        await generateAndUploadKeys(data.access_token);
      } else {
        setLoginResult(`Error: ${data.detail}`);
      }
    } catch (err) {
      setLoginResult(`Network error: ${err.message}`);
    }
  }

  async function handleSelectRecipient(email) {
    setRecipientEmail(email);
    setRecipientFingerprint("");

    const peer = await getPeerKeys(email);
    if (peer) {
      const fingerprint = await computeFingerprint(peer.publicKey, peer.signingKey);
      setRecipientFingerprint(fingerprint);
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

    setChatLog((prev) => [
      ...prev,
      { peer: recipientEmail, from: "me", text: messageText, verified: true, time: timestamp },
    ]);
    setMessageText("");
  }

  // Test button: re-sends the exact same signed message, simulating an attacker replaying it.
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

  function handleLogout() {
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
  const conversation = chatLog.filter((m) => m.peer === recipientEmail);
  const keysReady = keyStatus.startsWith("Encryption and signing keys ready");

  return (
    <div className="flex h-screen flex-col bg-slate-50">
      {/* Top bar */}
      <header className="flex items-center justify-between gap-4 border-b border-slate-200 bg-white px-5 py-3">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-lg text-white">
              🔒
            </div>
            <span className="hidden text-base font-bold text-slate-900 sm:block">Secure Messenger</span>
          </div>

          <nav className="flex gap-1">
            <button
              onClick={() => setView("chat")}
              className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                view === "chat" ? "bg-indigo-50 text-indigo-700" : "text-slate-500 hover:text-slate-800"
              }`}
            >
              Messages
            </button>
            {isAdmin && (
              <button
                onClick={() => setView("alerts")}
                className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                  view === "alerts" ? "bg-indigo-50 text-indigo-700" : "text-slate-500 hover:text-slate-800"
                }`}
              >
                Security alerts
                {unreviewedCount > 0 && (
                  <span className="rounded-full bg-red-600 px-2 py-0.5 text-[11px] font-semibold text-white">
                    {unreviewedCount}
                  </span>
                )}
              </button>
            )}
          </nav>
        </div>

        <div className="flex items-center gap-4">
          <div className="hidden items-center gap-2 text-xs text-slate-500 md:flex">
            <span className={`h-2 w-2 rounded-full ${keysReady ? "bg-emerald-500" : "bg-amber-400"}`}></span>
            {keysReady ? "Keys ready" : keyStatus}
            {myFingerprint && (
              <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">
                {myFingerprint}
              </code>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Avatar email={myEmailRef.current} size="h-8 w-8 text-xs" />
            <div className="hidden leading-tight sm:block">
              <p className="text-sm font-medium text-slate-800">{myEmailRef.current}</p>
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

      {/* Main area */}
      <main className="min-h-0 flex-1 overflow-hidden">
        {view === "chat" || !isAdmin ? (
          <Chat
            users={users}
            recipientEmail={recipientEmail}
            onSelect={handleSelectRecipient}
            recipientFingerprint={recipientFingerprint}
            messages={conversation}
            messageText={messageText}
            setMessageText={setMessageText}
            onSend={handleSendMessage}
            onReplay={handleReplayLast}
          />
        ) : (
          <div className="h-full overflow-y-auto">
            <AlertsPanel
              flags={flags}
              error={flagsError}
              showReviewed={showReviewed}
              setShowReviewed={setShowReviewed}
              onReview={markReviewed}
            />
          </div>
        )}
      </main>
    </div>
  );
}

export default App;