import { useState, useRef } from "react";

const MAX_MESSAGE_AGE_MS = 60 * 1000; // live messages older than 60 seconds are rejected

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
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regResult, setRegResult] = useState("");

  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginResult, setLoginResult] = useState("");
  const [token, setToken] = useState("");
  const [keyStatus, setKeyStatus] = useState("");
  const [myFingerprint, setMyFingerprint] = useState("");

  const [users, setUsers] = useState([]);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [recipientFingerprint, setRecipientFingerprint] = useState("");
  const [messageText, setMessageText] = useState("");
  const [chatLog, setChatLog] = useState([]);

  const keyPairRef = useRef(null);
  const signingKeyPairRef = useRef(null);
  const sharedKeysRef = useRef({});
  const verifyKeysRef = useRef({});
  const seenIdsRef = useRef(new Set());
  const lastSentRef = useRef(null);
  const wsRef = useRef(null);
  const myEmailRef = useRef("");
  const tokenRef = useRef("");

  async function handleRegister(e) {
    e.preventDefault();
    setRegResult("Registering...");
    try {
      const response = await fetch("http://127.0.0.1:8000/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: regEmail, password: regPassword }),
      });
      const data = await response.json();
      setRegResult(response.ok ? `Registered successfully: ${data.email}` : `Error: ${data.detail}`);
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
    setUsers(data.filter((u) => u.email !== myEmailRef.current));
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
            setChatLog((prev) => [...prev, { from: data.from, text: "[Rejected: message expired]", verified: false, rejected: true }]);
            return;
          }
        }
        if (seenIdsRef.current.has(data.msg_id)) {
          setChatLog((prev) => [...prev, { from: data.from, text: "[Rejected: replayed message]", verified: false, rejected: true }]);
          return;
        }
        seenIdsRef.current.add(data.msg_id);
      }

      // 3. Decrypt and display
      try {
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, peer.sharedKey, ciphertextBytes);
        const text = new TextDecoder().decode(decrypted);
        setChatLog((prev) => [...prev, { from: data.from, text, verified: signatureValid, offline: !!data.offline }]);
      } catch (err) {
        setChatLog((prev) => [...prev, { from: data.from, text: "[Could not decrypt message]", verified: false }]);
      }
    };

    wsRef.current = ws;
  }

  async function handleLogin(e) {
    e.preventDefault();
    setLoginResult("Logging in...");
    try {
      const response = await fetch("http://127.0.0.1:8000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
      });
      const data = await response.json();

      if (response.ok) {
        setToken(data.access_token);
        tokenRef.current = data.access_token;
        myEmailRef.current = loginEmail;
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
    if (!recipientEmail || !messageText || !wsRef.current) return;

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

    setChatLog((prev) => [...prev, { from: "me", text: messageText, verified: true }]);
    setMessageText("");
  }

  // Test button: re-sends the exact same signed message, simulating an attacker replaying it.
  function handleReplayLast() {
    if (!lastSentRef.current || !wsRef.current) return;
    wsRef.current.send(JSON.stringify(lastSentRef.current));
    setChatLog((prev) => [...prev, { from: "me", text: "[Replayed the last message for testing]", verified: true }]);
  }

  function handleLogout() {
    window.location.reload();
  }

  return (
    <div style={{ padding: "2rem", fontFamily: "sans-serif", maxWidth: "520px" }}>
      <h1>AI-Encrypted Communication System</h1>

      {!token && (
        <>
          <h2>Register</h2>
          <form onSubmit={handleRegister}>
            <div style={{ marginBottom: "1rem" }}>
              <label>Email</label><br />
              <input type="email" value={regEmail} onChange={(e) => setRegEmail(e.target.value)} required style={{ width: "100%", padding: "0.5rem" }} />
            </div>
            <div style={{ marginBottom: "1rem" }}>
              <label>Password</label><br />
              <input type="password" value={regPassword} onChange={(e) => setRegPassword(e.target.value)} required style={{ width: "100%", padding: "0.5rem" }} />
            </div>
            <button type="submit" style={{ padding: "0.5rem 1rem" }}>Register</button>
          </form>
          <p>{regResult}</p>

          <hr style={{ margin: "2rem 0" }} />

          <h2>Login</h2>
          <form onSubmit={handleLogin}>
            <div style={{ marginBottom: "1rem" }}>
              <label>Email</label><br />
              <input type="email" value={loginEmail} onChange={(e) => setLoginEmail(e.target.value)} required style={{ width: "100%", padding: "0.5rem" }} />
            </div>
            <div style={{ marginBottom: "1rem" }}>
              <label>Password</label><br />
              <input type="password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} required style={{ width: "100%", padding: "0.5rem" }} />
            </div>
            <button type="submit" style={{ padding: "0.5rem 1rem" }}>Login</button>
          </form>
          <p>{loginResult}</p>
          <p>{keyStatus}</p>
        </>
      )}

      {token && (
        <>
          <p>
            Logged in as <strong>{myEmailRef.current}</strong>{" "}
            <button onClick={handleLogout} style={{ marginLeft: "0.5rem", fontSize: "0.8rem" }}>Log out</button>
          </p>
          <p>{keyStatus}</p>
          {myFingerprint && (
            <p style={{ fontSize: "0.85rem", color: "#555" }}>
              Your key fingerprint: <code>{myFingerprint}</code>
            </p>
          )}

          <h2>Contacts</h2>
          {users.length === 0 && <p>No other users with uploaded keys yet.</p>}
          <ul>
            {users.map((u) => (
              <li key={u.email}>
                <button onClick={() => handleSelectRecipient(u.email)} style={{ fontWeight: recipientEmail === u.email ? "bold" : "normal" }}>
                  {u.email}
                </button>
              </li>
            ))}
          </ul>

          <h3>Messages</h3>
          <div style={{ border: "1px solid #ccc", padding: "1rem", height: "200px", overflowY: "auto", marginBottom: "1rem" }}>
            {chatLog.length === 0 && <p style={{ color: "#888" }}>No messages yet.</p>}
            {chatLog.map((m, i) => (
              <p key={i}>
                <strong>{m.from === "me" ? "You" : m.from}:</strong> {m.text}{" "}
                {m.from !== "me" && !m.rejected && (
                  <span style={{ fontSize: "0.75rem", color: m.verified ? "green" : "red" }}>
                    {m.verified ? "[signature verified]" : "[unverified / signature mismatch]"}
                  </span>
                )}
                {m.offline && (
                  <span style={{ fontSize: "0.75rem", color: "#555" }}> [received while you were offline]</span>
                )}
              </p>
            ))}
          </div>

          {recipientEmail && (
            <>
              <h3>Chat with {recipientEmail}</h3>
              {recipientFingerprint && (
                <p style={{ fontSize: "0.85rem", color: "#555" }}>
                  Their key fingerprint: <code>{recipientFingerprint}</code><br />
                  Compare this with {recipientEmail} out-of-band (in person or by call) to confirm you're not being intercepted.
                </p>
              )}
              <form onSubmit={handleSendMessage}>
                <input
                  type="text"
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  placeholder="Type an encrypted message..."
                  style={{ width: "80%", padding: "0.5rem" }}
                />
                <button type="submit" style={{ padding: "0.5rem 1rem" }}>Send</button>
              </form>
              <button onClick={handleReplayLast} style={{ marginTop: "1rem", padding: "0.4rem 0.8rem", fontSize: "0.8rem" }}>
                Replay last sent message (test)
              </button>
            </>
          )}
        </>
      )}
    </div>
  );
}

export default App;