import { useState } from "react";

function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState("");

  async function handleRegister(e) {
    e.preventDefault();
    setResult("Registering...");

    try {
      const response = await fetch("http://127.0.0.1:8000/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (response.ok) {
        setResult(`Registered successfully: ${data.email}`);
      } else {
        setResult(`Error: ${data.detail}`);
      }
    } catch (err) {
      setResult(`Network error: ${err.message}`);
    }
  }

  return (
    <div style={{ padding: "2rem", fontFamily: "sans-serif", maxWidth: "400px" }}>
      <h1>AI-Encrypted Communication System</h1>

      <h2>Register</h2>
      <form onSubmit={handleRegister}>
        <div style={{ marginBottom: "1rem" }}>
          <label>Email</label><br />
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{ width: "100%", padding: "0.5rem" }}
          />
        </div>

        <div style={{ marginBottom: "1rem" }}>
          <label>Password</label><br />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ width: "100%", padding: "0.5rem" }}
          />
        </div>

        <button type="submit" style={{ padding: "0.5rem 1rem" }}>Register</button>
      </form>

      <p>{result}</p>
    </div>
  );
}

export default App;