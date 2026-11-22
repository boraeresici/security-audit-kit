// Grader for the deep-review eval (promptfooconfig.deep.yaml). The verdict is graded by the shared
// triage grader, so REAL/FP is scored the same way in both evals. A case may also carry
// `max_severity` (F39): a REAL whose severity is above the impact its evidence shows fails.
import grade from "./grade.mjs";

export const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function severityOf(output) {
  const s = String(output);
  const end = s.lastIndexOf("}") + 1;
  // Reasoning models put prose before the JSON: widen from the last "{" until an object parses.
  for (let i = s.lastIndexOf("{"); i >= 0; i = i ? s.lastIndexOf("{", i - 1) : -1) {
    try {
      const v = JSON.parse(s.slice(i, end)).severity;
      return v ? String(v).toLowerCase() : null;
    } catch { /* not the start of the object */ }
  }
  return null;
}

export default function gradeDeep(output, context) {
  const base = grade(output, context);
  const max = String(context.vars.max_severity || "").toLowerCase();
  if (!base.pass || !max || String(context.vars.expected).toUpperCase() !== "REAL") return base;
  const sev = severityOf(output);
  const pass = sev in RANK && RANK[sev] <= RANK[max];
  return { pass, score: pass ? 1 : 0, reason: `${base.reason} severity=${sev} max=${max}` };
}
