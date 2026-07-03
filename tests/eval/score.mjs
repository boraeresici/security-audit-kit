// score.mjs — read a promptfoo eval output JSON and report precision/recall for the REAL class.
// Dev-only, zero deps. Usage: node score.mjs [output.json]
// Optional regression gates (exit 1 if unmet): EVAL_MIN_RECALL, EVAL_MIN_PRECISION (0-1).
import { readFileSync } from "node:fs";

const path = process.argv[2] || "output.json";
let doc;
try { doc = JSON.parse(readFileSync(path, "utf8")); }
catch (e) { console.error(`[score] cannot read ${path}: ${e.message}`); process.exit(2); }

// promptfoo output schema varies by version — locate the results array defensively.
function findResults(d) {
  if (Array.isArray(d?.results?.results)) return d.results.results;
  if (Array.isArray(d?.results)) return d.results;
  if (Array.isArray(d)) return d;
  return [];
}
const results = findResults(doc);
if (!results.length) { console.error(`[score] no results found in ${path}`); process.exit(2); }

function verdictFromText(t) {
  if (!t) return null;
  let s = String(t).trim().replace(/^```(json)?/i, "").replace(/```$/, "").trim();
  try { const v = JSON.parse(s).verdict; if (v) return String(v).toUpperCase(); } catch { /* fall through */ }
  const m = s.match(/\b(REAL|FP)\b/i);
  return m ? m[1].toUpperCase() : null;
}
function predictedOf(r) {
  const out = r?.response?.output ?? r?.output ?? r?.response?.text;
  let v = verdictFromText(typeof out === "string" ? out : JSON.stringify(out));
  if (v) return v;
  const reason = r?.gradingResult?.reason || (r?.gradingResult?.componentResults || []).map(c => c.reason).join(" ");
  const m = reason && reason.match(/predicted=(REAL|FP)/i);
  return m ? m[1].toUpperCase() : null;
}

let tp = 0, fp = 0, fn = 0, tn = 0, unknown = 0;
const rows = [];
for (const r of results) {
  const expected = String(r?.vars?.expected || "").toUpperCase();
  if (expected !== "REAL" && expected !== "FP") continue;
  const pred = predictedOf(r);
  if (pred !== "REAL" && pred !== "FP") {
    unknown++;
    // Unparseable prediction: safest accounting is "missed" on a REAL, "wrong" on an FP.
    if (expected === "REAL") fn++; else fp++;
    rows.push({ expected, pred: pred || "??", ok: false });
    continue;
  }
  const ok = pred === expected;
  if (expected === "REAL" && pred === "REAL") tp++;
  else if (expected === "FP" && pred === "REAL") fp++;
  else if (expected === "REAL" && pred === "FP") fn++;
  else tn++;
  rows.push({ expected, pred, ok });
}

const total = tp + fp + fn + tn;
const precision = tp + fp ? tp / (tp + fp) : 1;
const recall = tp + fn ? tp / (tp + fn) : 1;
const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
const accuracy = total ? (tp + tn) / total : 0;
const pct = x => (100 * x).toFixed(1) + "%";

console.log(`\n== sec-triage eval — ${total} labeled cases (positive class = REAL) ==`);
console.log(`  confusion:  TP=${tp}  FP=${fp}  FN=${fn}  TN=${tn}${unknown ? `  (unparseable=${unknown})` : ""}`);
console.log(`  precision:  ${pct(precision)}   (of findings called REAL, how many truly are)`);
console.log(`  recall:     ${pct(recall)}   (of true REAL findings, how many were caught)`);
console.log(`  f1:         ${pct(f1)}`);
console.log(`  accuracy:   ${pct(accuracy)}`);
const misses = rows.filter(r => !r.ok);
if (misses.length) {
  console.log(`  misses:     ` + misses.map(m => `${m.expected}->${m.pred}`).join(", "));
}

let code = 0;
const minR = process.env.EVAL_MIN_RECALL, minP = process.env.EVAL_MIN_PRECISION;
if (minR && recall < parseFloat(minR)) { console.error(`[score] recall ${pct(recall)} < EVAL_MIN_RECALL ${minR}`); code = 1; }
if (minP && precision < parseFloat(minP)) { console.error(`[score] precision ${pct(precision)} < EVAL_MIN_PRECISION ${minP}`); code = 1; }
process.exit(code);
