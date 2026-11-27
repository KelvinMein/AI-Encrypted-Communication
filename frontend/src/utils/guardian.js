import { analyse as scanMessage } from "./phishing";

// Turns what the app currently knows into a plain-language security summary.
// Rule-based: everything runs in the browser and nothing is sent anywhere.

const RANK = { good: 0, notice: 1, warning: 2 };

const HEADLINES = {
  good: "Your session looks secure",
  notice: "A few things need your attention",
  warning: "Security problems detected",
};

export function assess({ keysReady, wsStatus, messages = [], recipientEmail, isAdmin, flags = [] }) {
  const checks = [];
  const tips = [];
  let level = "good";
  const raise = (l) => {
    if (RANK[l] > RANK[level]) level = l;
  };

  // 1. Keys
  if (keysReady) {
    checks.push({
      state: "ok",
      label: "Encryption keys are ready",
      detail: "Messages are encrypted in this browser before they are sent.",
    });
  } else {
    checks.push({
      state: "warn",
      label: "Encryption keys are not ready yet",
      detail: "Wait for the Keys ready indicator before sending.",
    });
    raise("notice");
  }

  // 2. Connection to the relay
  if (wsStatus === "open") {
    checks.push({
      state: "ok",
      label: "Connected to the secure relay",
      detail: "Messages you send are delivered, or stored for offline contacts.",
    });
  } else if (wsStatus === "connecting") {
    checks.push({ state: "warn", label: "Connecting to the secure relay", detail: "This should only take a moment." });
    raise("notice");
  } else {
    checks.push({
      state: "bad",
      label: "Connection to the relay was lost",
      detail: "Messages you send now will not be delivered. Refresh the page and log in again.",
    });
    tips.push("Refresh the page and log in again to reconnect.");
    raise("warning");
  }

  // 3. What has been received
  const received = messages.filter((m) => m.from !== "me" && !m.system);
  const delivered = received.filter((m) => !m.rejected);
  const unverified = delivered.filter((m) => !m.verified).length;
  const replayed = received.filter((m) => m.rejected && /replayed/i.test(m.text)).length;
  const expired = received.filter((m) => m.rejected && /expired/i.test(m.text)).length;
  const undecryptable = received.filter((m) => m.rejected && /decrypt/i.test(m.text)).length;

  let risky = 0;
  let high = 0;
  for (const m of delivered) {
    const s = scanMessage(m.text);
    if (s.level === "medium" || s.level === "high") risky += 1;
    if (s.level === "high") high += 1;
  }

  if (delivered.length === 0) {
    checks.push({ state: "info", label: "No messages received yet", detail: "I will check each one as it arrives." });
  } else if (unverified > 0) {
    checks.push({
      state: "bad",
      label: `${unverified} message${unverified > 1 ? "s" : ""} failed the signature check`,
      detail: "They may not be from who they claim to be. Do not trust them.",
    });
    tips.push("Ask the sender to confirm by another channel before acting on an unverified message.");
    raise("warning");
  } else {
    checks.push({
      state: "ok",
      label: `All ${delivered.length} received message${delivered.length > 1 ? "s" : ""} passed the signature check`,
      detail: "Each one was signed by the person it says it came from.",
    });
  }

  const blocked = replayed + expired + undecryptable;
  if (blocked > 0) {
    const parts = [];
    if (replayed) parts.push(`${replayed} replayed`);
    if (expired) parts.push(`${expired} expired`);
    if (undecryptable) parts.push(`${undecryptable} could not be decrypted`);
    checks.push({
      state: "warn",
      label: `${blocked} message${blocked > 1 ? "s" : ""} blocked: ${parts.join(", ")}`,
      detail: "The app blocked these automatically. Repeated replays can mean someone is resending captured traffic.",
    });
    raise("notice");
  } else {
    checks.push({
      state: "ok",
      label: "No replayed or expired messages",
      detail: "Old or duplicated messages are rejected automatically.",
    });
  }

  if (risky > 0) {
    checks.push({
      state: high > 0 ? "bad" : "warn",
      label: `${risky} received message${risky > 1 ? "s" : ""} look suspicious`,
      detail: "They contain links or requests that match common scam patterns.",
    });
    tips.push("Do not open links or share PINs, passwords or one-time codes from messages that were flagged.");
    raise(high > 0 ? "warning" : "notice");
  } else {
    checks.push({
      state: "ok",
      label: "No suspicious links or requests in received messages",
      detail: "Links and wording are checked in your browser after each message is decrypted.",
    });
  }

  // 4. Administrator view
  const unreviewed = isAdmin ? flags.filter((f) => !f.reviewed) : [];
  if (isAdmin) {
    if (unreviewed.length > 0) {
      checks.push({
        state: "warn",
        label: `${unreviewed.length} unreviewed security alert${unreviewed.length > 1 ? "s" : ""}`,
        detail: "Raised by the AI detector from activity metadata.",
      });
      tips.push("Open Security alerts and review the new alerts.");
      raise("notice");
    } else {
      checks.push({
        state: "ok",
        label: "No unreviewed security alerts",
        detail: "The detector has not raised anything that needs review.",
      });
    }
  }

  if (recipientEmail) {
    tips.push(
      `Compare the key fingerprint with ${recipientEmail} in person or by phone. Matching codes prove nobody is intercepting your chat.`
    );
  }
  if (tips.length === 0) tips.push("Nothing needs your attention right now.");

  return { level, headline: HEADLINES[level], checks, tips, unreviewed };
}

// Plain-language explanation of an anomaly flag raised by the detector.
export function explainAlert(flag) {
  const r = flag.reason || "";
  const who = flag.subject === "network" ? "several accounts at once" : flag.subject;

  // "global_" must be checked before "failed_logins", because it contains that text
  if (r.includes("global_distinct_failed_emails") || r.includes("global_failed_logins")) {
    return {
      title: "Many accounts failing to log in",
      meaning:
        "Login attempts failed for many different accounts within seconds. This is typical of credential stuffing, where an attacker tries a list of stolen email and password pairs.",
      action:
        "Check the source in the activity log. The server limits repeated failures, but consider blocking the source if it continues.",
    };
  }
  if (r.includes("failed_logins")) {
    return {
      title: "Repeated failed logins",
      meaning: `Someone entered the wrong password for ${who} several times in a few seconds. This is typical of password guessing (a brute-force attack).`,
      action:
        "Check whether the account owner was mistyping. If not, ask them to change their password. The server already blocks the sixth attempt.",
    };
  }
  if (r.includes("msg_count")) {
    return {
      title: "Message flood",
      meaning: `${who} sent an unusually large number of messages in 10 seconds. This can be a spam bot or a flooding attack.`,
      action: "Contact the account owner. If it is not them, the account may be compromised.",
    };
  }
  if (r.includes("ws_connects") || r.includes("login_successes")) {
    return {
      title: "Rapid reconnecting",
      meaning: `${who} logged in or connected many times in a few seconds. A script or a faulty client can do this.`,
      action: "Check the activity log for the same account. If the pattern continues, treat it as automated.",
    };
  }
  return {
    title: "Unusual behaviour",
    meaning: `The behaviour of ${who} is unusual compared with normal use, but it does not match a known attack pattern.`,
    action:
      "Review the account's recent activity before acting. Alerts of this kind are more likely to be false alarms.",
  };
}

// Answers common security questions with fixed, explained replies.
export function answer(question, assessment, isAdmin) {
  const q = question.toLowerCase();

  if (/\bam i (safe|secure|ok)\b|\bis (my|this) (chat|session|account)\b|\bstatus\b|how (is|are) (my|everything)/.test(q)) {
    const problems = assessment.checks.filter((c) => c.state === "warn" || c.state === "bad");
    if (problems.length === 0) return `${assessment.headline}. All my checks passed.`;
    return `${assessment.headline}. ${problems.map((c) => c.label).join("; ")}.`;
  }

  if (/what should i do|advice|recommend|\btips?\b|next step/.test(q)) {
    return assessment.tips.join(" ");
  }

  if (/link|url|phish|scam|promo|prize|click|website|suspicious/.test(q)) {
    return (
      "Every message you receive is checked in your browser for risky links and wording, such as shortened links, look-alike websites, prize or urgency wording, and requests for PINs or codes. " +
      "If a message looks risky, its links are hidden until you choose to show them. " +
      "Never enter passwords, PINs or payment details on a site you reached from a message, and confirm unexpected requests with the sender by phone. " +
      "These checks use fixed rules, so a brand-new scam can slip through. Treat unexpected links with care even when there is no warning."
    );
  }

  if (/fingerprint|verify|identity|impersonat|man.in.the.middle|intercept/.test(q)) {
    return (
      "A fingerprint is a short code made from a person's public keys. Compare yours with your contact's, in person or by phone. " +
      "If both sides see the same codes, nobody has swapped the keys in between, which is what an interception attack would require."
    );
  }

  if (/signature|unverified|forg|tamper|mismatch/.test(q)) {
    return (
      "Every message is signed by the sender's private key, which never leaves their browser. Your browser checks the signature when a message arrives. " +
      "If it fails, the message may be forged or altered, so do not trust it."
    );
  }

  if (/replay|expired|rejected|duplicate/.test(q)) {
    return (
      "Each message has a unique ID and a timestamp that are covered by its signature. " +
      "Your browser rejects a message it has already seen, and live messages older than 60 seconds. This stops someone from resending captured traffic."
    );
  }

  if (/encrypt|private|privacy|server|read my|who can see|plaintext|end.to.end|e2e/.test(q)) {
    return (
      "Messages are encrypted in your browser before they are sent, and only the recipient's browser can decrypt them. " +
      "The server only stores ciphertext and activity details such as who messaged whom and how large the message was. It cannot read what you wrote."
    );
  }

  if (/password|login|log in|brute|locked|too many|429/.test(q)) {
    return (
      "After 5 wrong passwords for an account within a minute, further login attempts are refused for a short time, even with the right password. " +
      "This stops password guessing. Passwords are stored as one-way hashes, never as plain text."
    );
  }

  if (/offline|not online|logged out|miss/.test(q)) {
    return (
      "If a contact is offline, your message is stored on the server as ciphertext and delivered when they next log in. " +
      "It is still unreadable to the server while it waits."
    );
  }

  if (/alert|flag|bell|anomal|detector|isolation|score|false alarm/.test(q)) {
    if (!isAdmin) return "Security alerts are sent to the administrator only. They are based on activity patterns, not on message content.";
    return (
      "The detector watches activity details such as failed logins and message counts in a 10 second window, and raises an alert when behaviour looks unusual. " +
      "It never sees message content. Some alerts will be false alarms, so check the account's activity before acting."
    );
  }

  if (/^\s*(hi|hello|hey)\b/.test(q)) {
    return "Hello. Ask me whether your chat is safe, how to spot a scam, or what a fingerprint is.";
  }

  return "I can help with: whether your chat is safe, what you should do next, spotting scams, fingerprints, signatures, replay protection, privacy, logins, offline messages and alerts.";
}