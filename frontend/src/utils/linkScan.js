// Client-side message scanner.
// Runs in the RECEIVER'S browser after a message has been decrypted, so the server
// still never sees message content. Nothing is sent anywhere.

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
  "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
];

const SUSPICIOUS_TLDS = [
  "xyz", "top", "click", "link", "tk", "ml", "ga", "cf", "gq",
  "work", "loan", "rest", "support", "country", "icu", "buzz",
];

// Brands that scammers commonly imitate. Edit this list to suit.
const BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "instagram", "netflix", "whatsapp", "safaricom", "mpesa",
];

const URGENCY = /\b(urgent|act now|immediately|limited time|expires?|last chance|hurry|today only)\b/i;
const PRIZE = /\b(winner|you('ve| have)? won|prize|free|claim|congratulations|gift|giveaway|bonus|reward|promo(tion)?|discount|double your)\b/i;
const ACCOUNT = /\b(verify your|confirm your|account (has been )?(suspended|locked|limited)|password|sign in|security alert|update your (details|account|information))\b/i;
const MONEY = /\b(bitcoin|crypto|investment|forex|loan|get rich|earn \$?\d+)\b/i;
const SENSITIVE = /\b(otp|pin|cvv|one[- ]time (code|password)|passcode|card number)\b/i;

const END = "[^\\s<>\"']*[^\\s<>\"'.,;:!?)\\]]";
const URL_SOURCE =
  "(\\b(?:https?:\\/\\/|www\\.)" + END + "|\\b(?:" +
  SHORTENERS.map((s) => s.replace(/\./g, "\\.")).join("|") +
  ")\\/" + END + ")";
const URL_RE = new RegExp(URL_SOURCE, "i");

function registeredLabel(host) {
  const labels = host.split(".");
  const last = labels[labels.length - 1];
  const second = labels[labels.length - 2];
  if (labels.length >= 3 && last.length === 2 && ["co", "com", "org", "net", "ac", "go", "or", "ne"].includes(second)) {
    return labels[labels.length - 3];
  }
  return second || host;
}

function analyseUrl(raw) {
  const reasons = [];
  let points = 0;
  const add = (p, r) => {
    points += p;
    reasons.push(r);
  };

  const hasScheme = /^https?:\/\//i.test(raw);
  let url;
  try {
    url = new URL(hasScheme ? raw : "http://" + raw);
  } catch {
    return { points: 1, reasons: ["The link could not be read properly"] };
  }

  const host = url.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];

  if (hasScheme && url.protocol === "http:") add(1, "The link is not encrypted (http, not https)");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(3, "The link goes to a raw IP address, not a normal website name");
  if (host.includes("xn--")) add(3, "The address uses lookalike characters that imitate another site");
  if (url.username || url.password) add(3, "The address contains an '@' trick that disguises the real site");
  if (SHORTENERS.some((s) => host === s || host.endsWith("." + s))) add(2, "A shortened link hides the real destination");
  if (SUSPICIOUS_TLDS.includes(tld)) add(2, `The domain ending .${tld} is often used for scams`);
  if (labels.length >= 5) add(1, "The address has an unusually long chain of subdomains");

  const label = registeredLabel(host);
  if ((label.match(/-/g) || []).length >= 2) add(1, "The domain name has many hyphens");
  const brand = BRANDS.find((b) => host.includes(b) && label !== b);
  if (brand) add(3, `The address mentions "${brand}" but is not the real ${brand} website`);
  if (raw.length > 100) add(1, "The link is unusually long");

  return { points, reasons, host };
}

export function scanMessage(text) {
  const pieces = text.split(URL_RE);
  const parts = pieces.map((value, i) => ({ type: i % 2 === 1 ? "link" : "text", value }));
  const linkValues = parts.filter((p) => p.type === "link").map((p) => p.value);

  let score = 0;
  const reasons = [];
  const addReason = (r) => {
    if (!reasons.includes(r)) reasons.push(r);
  };

  for (const raw of linkValues) {
    const a = analyseUrl(raw);
    score += a.points;
    a.reasons.forEach(addReason);
  }

  if (linkValues.length >= 3) {
    score += 1;
    addReason("The message contains several links");
  }

  if (linkValues.length > 0) {
    if (URGENCY.test(text)) { score += 1; addReason("It pressures you to act quickly"); }
    if (PRIZE.test(text)) { score += 1; addReason("It uses prize, free or promotion wording"); }
    if (ACCOUNT.test(text)) { score += 1; addReason("It talks about verifying or securing an account"); }
    if (MONEY.test(text)) { score += 1; addReason("It mentions money, loans or investments"); }
  }

  if (SENSITIVE.test(text)) {
    score += 3;
    addReason("It mentions a PIN, password or one-time code");
  }

  let level = "none";
  if (score >= 5) level = "high";
  else if (score >= 3) level = "medium";
  else if (score >= 1 && linkValues.length > 0) level = "low";

  return { parts, links: linkValues, level, score, reasons };
}

// Makes a link safe to display: hxxps://bit[.]ly/abc (not clickable)
export function defang(value) {
  return value.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

export function toHref(value) {
  return /^https?:\/\//i.test(value) ? value : "https://" + value;
}