import { useState } from "react";

function App() {
  // Registration state
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regResult, setRegResult] = useState("");

  // Login state
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginResult, setLoginResult] = useState("");
  const [token, setToken] = useState("");
  const [keyStatus, setKeyStatus] = useState("");

  // Keeps the private key in memory only, never sent anywhere
  const [keyPair, setKeyPair] = useState(null);

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

  async function generateAndUploadKeys(jwtToken) {
    setKeyStatus("Generating encryption keys...");

    // Generate an ECDH key pair in the browser
    const pair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );
    setKeyPair(pair);

    // Export the public key so it can be sent to the backend as text
    const rawPublicKey = await crypto.subtle.exportKey("raw", pair.publicKey);
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(rawPublicKey)));

    setKeyStatus("Uploading public key...");

    const response = await fetch("http://127.0.0.1:8000/upload-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${jwtToken}`,
      },
      body: JSON.stringify({ public_key: publicKeyBase64 }),
    });

    if (response.ok) {
      setKeyStatus("Encryption keys ready. Public key uploaded.");
    } else {
      const data = await response.json();
      setKeyStatus(`Key upload failed: ${data.detail}`);
    }
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
        setLoginResult("Login successful.");
        await generateAndUploadKeys(data.access_token);
      } else {
        setLoginResult(`Error: ${data.detail}`);
      }
    } catch (err) {
      setLoginResult(`Network error: ${err.message}`);
    }
  }

  return (
    <div style={{ padding: "2rem", fontFamily: "sans-serif", maxWidth: "400px" }}>
      <h1>AI-Encrypted Communication System</h1>

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

      {token && (
        <div style={{ marginTop: "1rem", wordBreak: "break-all", fontSize: "0.8rem", color: "#555" }}>
          <strong>Token:</strong> {token}
        </div>
      )}
    </div>
  );
}

export default App;