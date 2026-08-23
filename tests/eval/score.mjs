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

// A case where the request never reached the model (auth, billing, network, bad model id) carries
// NO information about judgment quality. promptfoo marks these failureReason=2 with no
// response.output — as opposed to failureReason=1, a real answer that failed the assertion.
// Scoring them as misses turns "the provider is down" into "the model scored 0%", which reads as a
// catastrophic regression. Refuse to report instead; a missing number is honest, a wrong one isn't.
const isProviderError = r => r?.failureReason === 2 || (!!r?.error && !r?.response?.output);

// One config may now carry several providers so a single run yields a comparable table. Results
// MUST be grouped: pooling two backends into one confusion matrix reports a model that does not
// exist. With one provider the output is unchanged.
function providerOf(r) {
  const p = r?.provider;
  return (typeof p === "string" ? p : p?.label || p?.id) || r?.providerId || "(provider)";
}
const groups = new Map();
for (const r of results) {
  const k = providerOf(r);
  if (!groups.has(k)) groups.set(k, []);
  groups.get(k).push(r);
}

const pct = x => (100 * x).toFixed(1) + "%";

// -> { ok:false, reason } when the run carries no usable signal, else the metrics.
function scoreOf(rs) {
  const errs = rs.filter(isProviderError);
  const allowPartial = !!process.env.EVAL_ALLOW_PARTIAL;
  let tp = 0, fp = 0, fn = 0, tn = 0, unknown = 0;
  const rows = [];
  for (const r of rs) {
    const expected = String(r?.vars?.expected || "").toUpperCase();
    if (expected !== "REAL" && expected !== "FP") continue;
    if (isProviderError(r)) continue;   // never charge an infrastructure failure to the model
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
  // Zero scored cases must never render as a score: the empty-denominator guards below default
  // precision/recall to 1, so an all-errored run would print a perfect 100% and exit 0.
  if (total === 0) return { ok: false, errs: errs.length, reason: "no case reached the model" };
  if (errs.length && !allowPartial) {
    return { ok: false, errs: errs.length, partial: true, first: String(errs[0].error || "").slice(0, 160),
             reason: `${errs.length}/${rs.length} cases never reached the model` };
  }
  const precision = tp + fp ? tp / (tp + fp) : 1;
  const recall = tp + fn ? tp / (tp + fn) : 1;
  return {
    ok: true, tp, fp, fn, tn, unknown, total, errs: errs.length, precision, recall,
    f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
    accuracy: (tp + tn) / total,
    misses: rows.filter(r => !r.ok),
  };
}

const scored = [...groups.entries()].map(([name, rs]) => [name, scoreOf(rs)]);
let code = 0;
const minR = process.env.EVAL_MIN_RECALL, minP = process.env.EVAL_MIN_PRECISION;

function gate(name, s) {
  const tag = scored.length > 1 ? `${name}: ` : "";
  if (minR && s.recall < parseFloat(minR)) {
    console.error(`[score] ${tag}recall ${pct(s.recall)} < EVAL_MIN_RECALL ${minR}`); code = 1;
  }
  if (minP && s.precision < parseFloat(minP)) {
    console.error(`[score] ${tag}precision ${pct(s.precision)} < EVAL_MIN_PRECISION ${minP}`); code = 1;
  }
}

if (scored.length === 1) {
  const [name, s] = scored[0];
  if (!s.ok) {
    console.error(`\n[score] ${s.reason}${s.first ? ` (first error: ${s.first})` : ""}.`);
    if (s.partial) {
      console.error(`[score] refusing to report precision/recall — a failed provider is not a bad model.`);
      console.error(`[score] fix the provider, or set EVAL_ALLOW_PARTIAL=1 to score only the cases that ran.`);
    } else {
      console.error(`[score] nothing to score. This is not a 100%.`);
    }
    process.exit(2);
  }
  const skipped = s.errs ? ` — ${s.errs} skipped (provider error)` : "";
  console.log(`\n== sec-triage eval — ${s.total} labeled cases (positive class = REAL)${skipped} ==`);
  console.log(`  provider:   ${name}`);
  console.log(`  confusion:  TP=${s.tp}  FP=${s.fp}  FN=${s.fn}  TN=${s.tn}${s.unknown ? `  (unparseable=${s.unknown})` : ""}`);
  console.log(`  precision:  ${pct(s.precision)}   (of findings called REAL, how many truly are)`);
  console.log(`  recall:     ${pct(s.recall)}   (of true REAL findings, how many were caught)`);
  console.log(`  f1:         ${pct(s.f1)}`);
  console.log(`  accuracy:   ${pct(s.accuracy)}`);
  if (s.misses.length) console.log(`  misses:     ` + s.misses.map(m => `${m.expected}->${m.pred}`).join(", "));
  gate(name, s);
} else {
  // Head-to-head: one row per backend, same corpus, same prompt, same grader, one run.
  const w = Math.max(8, ...scored.map(([n]) => n.length));
  console.log(`\n== sec-triage eval — ${scored.length} backends, same corpus + prompt + grader ==`);
  console.log(`  ${"backend".padEnd(w)}  cases  prec    recall  f1      acc     confusion`);
  for (const [name, s] of scored) {
    if (!s.ok) {
      console.log(`  ${name.padEnd(w)}  ${String("—").padStart(5)}  not measured — ${s.reason}`);
      continue;                       // a dead provider must not sink the other rows
    }
    console.log(
      `  ${name.padEnd(w)}  ${String(s.total).padStart(5)}  ${pct(s.precision).padEnd(6)}  ` +
      `${pct(s.recall).padEnd(6)}  ${pct(s.f1).padEnd(6)}  ${pct(s.accuracy).padEnd(6)}  ` +
      `TP=${s.tp} FP=${s.fp} FN=${s.fn} TN=${s.tn}${s.unknown ? ` (unparseable=${s.unknown})` : ""}`
    );
    gate(name, s);
  }
  const measured = scored.filter(([, s]) => s.ok).length;
  if (!measured) { console.error(`[score] no backend produced a usable result.`); process.exit(2); }
  console.log(`\n  ${measured}/${scored.length} backends measured. Differences under ~1 case are noise.`);
}
process.exit(code);
