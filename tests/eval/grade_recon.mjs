// Grader for the recon eval (promptfooconfig.recon.yaml): where does the model rank the planted
// flaw? A case passes at rank 1. The rank goes into the reason, where score_recon.mjs reads it.
export function candidatesOf(output) {
  const s = String(output);
  const end = s.lastIndexOf("}") + 1;
  // Reasoning models put prose before the JSON: widen from the last "{" until an object parses.
  for (let i = s.lastIndexOf("{"); i >= 0; i = i ? s.lastIndexOf("{", i - 1) : -1) {
    try {
      const c = JSON.parse(s.slice(i, end)).candidates;
      if (Array.isArray(c)) return c;
    } catch { /* not the start of the object */ }
  }
  return null;
}

export function rankOf(output, expectedFile) {
  const cands = candidatesOf(output);
  if (!cands) return null;
  const want = String(expectedFile).replace(/^\.\//, "");
  const i = cands.findIndex(c => String(c?.file || "").replace(/^\.\//, "").split(":")[0] === want);
  return i < 0 ? 0 : i + 1;   // 0 = listed nowhere
}

export default function gradeRecon(output, context) {
  const rank = rankOf(output, context.vars.expected_file);
  const pass = rank === 1;
  return { pass, score: pass ? 1 : 0, reason: `rank=${rank === null ? "unparseable" : rank} expected=${context.vars.expected_file}` };
}
