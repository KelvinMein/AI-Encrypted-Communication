// Scores a message with the trained text model. Pure functions, no network:
// this mirrors scikit-learn's TF-IDF vectoriser and logistic regression exactly.

const URL_RE = /(https?:\/\/\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|net|org|xyz|top|click|link|ly|co|info|biz)\b\S*)/gi;

function normalise(text) {
  return text.toLowerCase().replace(URL_RE, " urltoken ");
}

export function scoreText(model, text) {
  const tokens = normalise(text).match(/[a-z0-9']+/g) || [];
  const counts = new Map();
  const add = (term) => {
    const idx = model.vocabulary[term];
    if (idx !== undefined) counts.set(idx, (counts.get(idx) || 0) + 1);
  };
  for (const t of tokens) add(t);
  for (let i = 0; i < tokens.length - 1; i++) add(tokens[i] + " " + tokens[i + 1]);

  const weights = new Map();
  let norm = 0;
  for (const [idx, c] of counts) {
    const v = (1 + Math.log(c)) * model.idf[idx];
    weights.set(idx, v);
    norm += v * v;
  }
  norm = Math.sqrt(norm);

  let z = model.intercept;
  const contributions = [];
  if (norm > 0) {
    for (const [idx, v] of weights) {
      const part = model.coef[idx] * (v / norm);
      z += part;
      contributions.push([idx, part]);
    }
  }
  return { probability: 1 / (1 + Math.exp(-z)), contributions };
}

// The words that pushed the score up the most, for the explanation shown to the user
export function topTerms(model, contributions, n = 3) {
  if (!model._terms) {
    model._terms = [];
    for (const [term, idx] of Object.entries(model.vocabulary)) model._terms[idx] = term;
  }
  return contributions
    .filter(([, part]) => part > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([idx]) => (model._terms[idx] === "urltoken" ? "a link" : model._terms[idx]));
}