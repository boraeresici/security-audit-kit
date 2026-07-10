// Shared REAL/FP grader for every eval backend (promptfoo `javascript` assertion, file:// form).
//
// One grader for all promptfooconfig.*.yaml so a scoring change can never land on one backend and
// not the others — that would silently make cross-backend scores non-comparable, which is the whole
// point of the harness.
//
// promptfoo calls this as `default(output, context)` and accepts a GradingResult object back.
// Models are asked for JSON but routinely wrap it in a ```json fence or prepend prose, so parse
// leniently and fall back to scanning for a bare REAL/FP token. A verdict of null (no parse, no
// token) fails the case — an unreadable answer is a wrong answer.
export default function grade(output, context) {
  const out = String(output)
    .trim()
    .replace(/^```(json)?/i, '')
    .replace(/```$/, '')
    .trim();

  let verdict = null;
  try {
    verdict = JSON.parse(out).verdict;
  } catch {
    const m = out.match(/\b(REAL|FP)\b/i);
    verdict = m ? m[1] : null;
  }
  verdict = verdict ? String(verdict).toUpperCase() : null;

  const expected = String(context.vars.expected || '').toUpperCase();
  const pass = verdict === expected;
  return { pass, score: pass ? 1 : 0, reason: `predicted=${verdict} expected=${expected}` };
}
