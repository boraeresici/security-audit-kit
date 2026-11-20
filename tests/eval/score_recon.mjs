// score_recon.mjs — read a promptfoo output of the recon eval and report hit@1 / hit@2 per card.
// Dev-only, zero deps. Usage: node score_recon.mjs [output.json]
import { readFileSync } from "node:fs";
import { rankOf } from "./grade_recon.mjs";

const path = process.argv[2] || "output.recon.json";
let doc;
try { doc = JSON.parse(readFileSync(path, "utf8")); }
catch (e) { console.error(`[score] cannot read ${path}: ${e.message}`); process.exit(2); }
const results = Array.isArray(doc?.results?.results) ? doc.results.results : [];

const isError = r => !!r?.error && !r?.response?.output;
const rows = [];
let errors = 0;
for (const r of results) {
  if (isError(r)) { errors++; continue; }    // a failed provider is not a bad model
  const rank = rankOf(r?.response?.output ?? "", r?.vars?.expected_file);
  rows.push({ card: r?.testCase?.metadata?.card || r?.metadata?.card || "?", rank,
              distractors: r?.testCase?.metadata?.distractors ?? r?.metadata?.distractors });
}
if (!rows.length) { console.error(`[score] no case reached the model (${errors} errors). This is not a 100%.`); process.exit(2); }
if (errors && !process.env.EVAL_ALLOW_PARTIAL) {
  console.error(`[score] ${errors}/${results.length} cases never reached the model; set EVAL_ALLOW_PARTIAL=1 to score the rest.`);
  process.exit(2);
}

const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : "—");
const line = (label, rs) => {
  const h1 = rs.filter(r => r.rank === 1).length, h2 = rs.filter(r => r.rank === 1 || r.rank === 2).length;
  // A random pick of the first file lands on the flaw 1 time in (distractors + 1).
  const chance = rs.reduce((a, r) => a + 1 / ((r.distractors ?? 3) + 1), 0) / rs.length;
  console.log(`  ${label.padEnd(6)} n=${String(rs.length).padStart(3)}  hit@1 ${pct(h1, rs.length).padEnd(6)}  ` +
              `hit@2 ${pct(h2, rs.length).padEnd(6)}  missed ${rs.filter(r => r.rank === 0).length}  ` +
              `unparseable ${rs.filter(r => r.rank === null).length}  (chance hit@1 ≈ ${pct(chance, 1)})`);
};
console.log(`\n== recon eval — ${rows.length} cases${errors ? `, ${errors} skipped (provider error)` : ""} ==`);
line("all", rows);
for (const card of [...new Set(rows.map(r => r.card))].sort()) line(card, rows.filter(r => r.card === card));
