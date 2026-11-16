// Pure, plain-Node-testable logic for the "Sentiment"-style results view: live vote share per option, and
// whether a given answer matches the poll's resolved outcome. No wasm or network imports (unlike lib.ts), so
// plain `node --test` can run this file directly.
export type Answers = Record<string, number | number[] | string>;

/** Vote share per option (0-100), single/multi-choice questions only. A set: picking an option twice
 *  (e.g. [0,0,0] for "none of the above" in a multi question) still counts as one respondent for it. */
export function shares(responses: Record<string, { answers_json: string }>, q: { id: string; options: string[] }): number[] {
  const counts = q.options.map(() => 0);
  let n = 0;
  for (const r of Object.values(responses)) {
    const v = (JSON.parse(r.answers_json) as Answers)[q.id];
    if (v === undefined) continue;
    n++;
    new Set(([] as number[]).concat(v as number | number[])).forEach((i) => counts[i]++);
  }
  return counts.map((c) => (n ? (c / n) * 100 : 0));
}

/** Whether `answers` picked the resolved `outcome` for question `qid` (single/multi: same option set).
 *  Null when either side never answered that question (text/avail, or an optional question left blank). */
export function isCorrect(answers: Answers, outcome: Answers, qid: string): boolean | null {
  if (!(qid in outcome) || !(qid in answers)) return null;
  const norm = (v: Answers[string]) => JSON.stringify([...new Set(([] as number[]).concat(v as number | number[]))].sort());
  return norm(answers[qid]) === norm(outcome[qid]);
}
