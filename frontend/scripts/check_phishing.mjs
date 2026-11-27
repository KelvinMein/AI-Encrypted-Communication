// Checks that the browser code gives the same answers as Python on the reference messages.
// Run from the frontend folder:  node scripts\check_phishing.mjs
import fs from "node:fs";
import { scoreText } from "../src/utils/phishingScore.js";

const model = JSON.parse(fs.readFileSync(new URL("../public/phishing_model.json", import.meta.url)));
let worst = 0;
for (const ref of model.reference) {
  const { probability } = scoreText(model, ref.text);
  const diff = Math.abs(probability - ref.probability);
  worst = Math.max(worst, diff);
  console.log(`python ${ref.probability.toFixed(4)}  browser ${probability.toFixed(4)}  ${ref.text.slice(0, 55)}`);
}
console.log(worst < 1e-3 ? "\nPASS: browser and Python agree" : "\nMISMATCH: do not use this model until this is fixed");