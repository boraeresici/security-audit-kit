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

function rawTextOf(r) {
  const out = r?.response?.output ?? r?.output ?? r?.response?.text;
  return typeof out === "string" ? out : out ? JSON.stringify(out) : null;
}

// Models with chain-of-thought (Qwen thinking, GLM reasoning_content) prepend free-text
// reasoning before the structured JSON response. Locate the LAST {...} block — that is where
// the structured verdict lives. Falls back to the trimmed text if no JSON object is found.
function extractJsonBlock(text) {
  if (!text) return text;
  const s = String(text).trim().replace(/^```(json)?/i, "").replace(/```$/, "").trim();
  // Try direct parse first (clean output, no thinking prefix).
  try { JSON.parse(s); return s; } catch { /* not clean JSON */ }
  // Find the last balanced {...} — models put reasoning BEFORE the answer.
  let depth = 0, end = -1;
  for (let i = s.length - 1; i >= 0; i--) {
    if (s[i] === "}") { if (depth === 0) end = i; depth++; }
    else if (s[i] === "{") { depth--; if (depth === 0 && end >= 0) return s.slice(i, end + 1); }
  }
  return s;   // no JSON block found — return as-is for regex fallback
}

function verdictFromText(t) {
  if (!t) return null;
  const s = extractJsonBlock(t);
  try { const v = JSON.parse(s).verdict; if (v) return String(v).toUpperCase(); } catch { /* fall through */ }
  const m = s.match(/\b(REAL|FP)\b/i);
  return m ? m[1].toUpperCase() : null;
}
function predictedOf(r) {
  let v = verdictFromText(rawTextOf(r));
  if (v) return v;
  const reason = r?.gradingResult?.reason || (r?.gradingResult?.componentResults || []).map(c => c.reason).join(" ");
  const m = reason && reason.match(/predicted=(REAL|FP)/i);
  return m ? m[1].toUpperCase() : null;
}

// Confidence is the model's self-assessed P(this finding is REAL) in [0,1]. It lives in the
// same JSON object the verdict comes from. null when the model didn't emit one or the output
// was unparseable as JSON (regex-fallback verdicts carry no confidence).
function confidenceOf(r) {
  const text = rawTextOf(r);
  if (!text) return null;
  const s = extractJsonBlock(text);
  try { const c = JSON.parse(s).confidence; return typeof c === "number" ? c : null; } catch { return null; }
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

// Calibration: is the model's confidence a trustworthy probability?
// Academic metrics (Brier, ECE, reliability bins) answer "how well-calibrated is this model?"
// Product metrics (threshold cost) answer "does the 0.7 cutoff hurt users?"
function calibrationOf(rows) {
  const withConf = rows.filter(r => r.conf != null);
  if (withConf.length < 3) return null;   // too few to be meaningful

  // Brier score: mean squared error of confidence as P(REAL).
  // A perfectly calibrated model scores 0; a maximally wrong one scores 1.
  let brierSum = 0;
  for (const r of withConf) {
    const actual = r.expected === "REAL" ? 1 : 0;
    brierSum += (r.conf - actual) ** 2;
  }
  const brier = brierSum / withConf.length;

  // Reliability table: 5 equal-width bins from 0 to 1.
  // For each bin: how many predictions landed there, their mean confidence, and the fraction
  // that were actually REAL. A calibrated model has avg_conf ≈ actual_rate in every bin.
  const BIN_EDGES = [0, 0.2, 0.4, 0.6, 0.8, 1.001];
  const bins = [];
  for (let i = 0; i < BIN_EDGES.length - 1; i++) {
    const lo = BIN_EDGES[i], hi = BIN_EDGES[i + 1];
    const inBin = withConf.filter(r => r.conf >= lo && r.conf < hi);
    if (!inBin.length) continue;
    const avgConf = inBin.reduce((s, r) => s + r.conf, 0) / inBin.length;
    const actualRate = inBin.filter(r => r.expected === "REAL").length / inBin.length;
    bins.push({ lo, hi: Math.min(hi, 1), n: inBin.length, avgConf, actualRate, gap: avgConf - actualRate });
  }

  // ECE: weighted mean of |avg_conf - actual_rate| across bins.
  const ece = bins.reduce((s, b) => s + (b.n / withConf.length) * Math.abs(b.gap), 0);

  // Threshold cost analysis at 0.7 — the two numbers that tell the product team whether the
  // cutoff is in the right place. These are NOT academic metrics; they are what the user feels.
  //
  // Suppressed REALs: the model said REAL but confidence < 0.7. In the shipped product these
  // become FP (the threshold flips them) and land in the Suppressed section — real findings
  // the user never sees.
  const suppressedREAL = withConf.filter(r => r.expected === "REAL" && r.pred === "REAL" && r.conf < 0.7);
  // Noise FP: the model said REAL with confidence ≥ 0.7 but the finding is actually FP.
  // These leak into the report as false alarms the user has to dismiss.
  const noiseFP = withConf.filter(r => r.expected === "FP" && r.pred === "REAL" && r.conf >= 0.7);

  return { brier, ece, bins, n: withConf.length, suppressedREAL: suppressedREAL.length, noiseFP: noiseFP.length };
}

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
    const conf = confidenceOf(r);
    if (pred !== "REAL" && pred !== "FP") {
      unknown++;
      // Unparseable prediction: safest accounting is "missed" on a REAL, "wrong" on an FP.
      if (expected === "REAL") fn++; else fp++;
      rows.push({ expected, pred: pred || "??", ok: false, conf });
      continue;
    }
    const ok = pred === expected;
    if (expected === "REAL" && pred === "REAL") tp++;
    else if (expected === "FP" && pred === "REAL") fp++;
    else if (expected === "REAL" && pred === "FP") fn++;
    else tn++;
    rows.push({ expected, pred, ok, conf });
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
    calibration: calibrationOf(rows),
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

function printCalibration(cal, indent = "  ") {
  if (!cal) { console.log(`${indent}calibration: not available (too few cases with confidence)`); return; }
  console.log(`${indent}calibration: ${cal.n}/${cal.n} cases had confidence`);
  console.log(`${indent}  Brier:    ${cal.brier.toFixed(4)}   (0 = perfect, lower = better)`);
  console.log(`${indent}  ECE:      ${cal.ece.toFixed(4)}   (weighted calibration error across bins)`);
  console.log(`${indent}  reliability (conf bin → n, avg_conf, actual_rate, gap):`);
  for (const b of cal.bins) {
    const label = `${b.lo.toFixed(1)}-${b.hi.toFixed(1)}`;
    console.log(`${indent}    ${label.padEnd(7)} n=${String(b.n).padStart(3)}  ` +
      `avg_conf=${b.avgConf.toFixed(3)}  actual=${b.actualRate.toFixed(3)}  ` +
      `gap=${b.gap >= 0 ? "+" : ""}${b.gap.toFixed(3)}`);
  }
  console.log(`${indent}  threshold cost @ 0.7:`);
  console.log(`${indent}    suppressed REALs: ${cal.suppressedREAL}   (real findings lost below the cutoff)`);
  console.log(`${indent}    noise FPs:        ${cal.noiseFP}   (false alarms that passed the cutoff)`);
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
  printCalibration(s.calibration);
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
  // Per-backend calibration — same order as the table above.
  console.log(`\n  -- calibration (confidence as P(REAL)) --`);
  for (const [name, s] of scored) {
    if (!s.ok || !s.calibration) continue;
    console.log(`  [${name}]`);
    printCalibration(s.calibration, "    ");
  }
}
process.exit(code);
