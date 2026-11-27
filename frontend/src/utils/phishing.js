import { scanMessage } from "./linkScan";
import { scoreText, topTerms } from "./phishingScore";

// The trained model is loaded once in the background. If it can't be loaded,
// everything keeps working with the link and wording rules alone.
let model = null;
fetch("/phishing_model.json")
  .then((r) => (r.ok ? r.json() : null))
  .then((m) => {
    model = m;
  })
  .catch(() => {});

// Rules (links, look-alike sites, urgency, PIN requests) plus the trained wording model.
// Runs in the receiver's browser after decryption, so the server never sees message content.
export function analyse(text) {
  const base = scanMessage(text);
  if (!model) return { ...base, modelProbability: null };

  const { probability, contributions } = scoreText(model, text);
  if (probability < model.threshold) return { ...base, modelProbability: probability };

  const terms = topTerms(model, contributions, 3);
  const reasons = [
    ...base.reasons,
    terms.length
      ? `The wording is similar to known scam and promotion messages (${terms.join(", ")})`
      : "The wording is similar to known scam and promotion messages",
  ];
  const score = base.score + 3;
  let level = "none";
  if (score >= 5) level = "high";
  else if (score >= 3) level = "medium";
  else if (score >= 1 && base.links.length > 0) level = "low";

  return { ...base, score, reasons, level, modelProbability: probability };
}