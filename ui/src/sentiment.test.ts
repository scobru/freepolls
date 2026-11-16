import test from "node:test";
import assert from "node:assert/strict";
import { donutArcs, isCorrect, shares } from "./sentiment.ts";

const q = { id: "q1", options: ["Yes", "No"] };

const resp = (answers: Record<string, unknown>) => ({ answers_json: JSON.stringify(answers) });

test("shares: percentage of respondents who picked each option", () => {
  const responses = { a: resp({ q1: 0 }), b: resp({ q1: 0 }), c: resp({ q1: 1 }) };
  assert.deepEqual(shares(responses, q), [(2 / 3) * 100, (1 / 3) * 100]);
});

test("shares: no responses is all zero, not NaN", () => {
  assert.deepEqual(shares({}, q), [0, 0]);
});

test("shares: a response missing the question doesn't count toward the total", () => {
  const responses = { a: resp({ q1: 0 }), b: resp({ other: 1 }) };
  assert.deepEqual(shares(responses, q), [100, 0]);
});

test("isCorrect: single-choice matches by option index", () => {
  assert.equal(isCorrect({ q1: 0 }, { q1: 0 }, "q1"), true);
  assert.equal(isCorrect({ q1: 1 }, { q1: 0 }, "q1"), false);
});

test("isCorrect: multi-choice matches regardless of order", () => {
  assert.equal(isCorrect({ q1: [1, 0] }, { q1: [0, 1] }, "q1"), true);
  assert.equal(isCorrect({ q1: [0] }, { q1: [0, 1] }, "q1"), false);
});

test("isCorrect: null when either side never answered that question", () => {
  assert.equal(isCorrect({}, { q1: 0 }, "q1"), null);
  assert.equal(isCorrect({ q1: 0 }, {}, "q1"), null);
});

test("donutArcs: two equal halves cover the full circle with no gap", () => {
  const c = 2 * Math.PI * 10;
  const arcs = donutArcs([50, 50], 10);
  assert.equal(arcs[0].dashoffset, 0);
  assert.equal(arcs[0].dasharray, `${c / 2} ${c / 2}`);
  assert.equal(arcs[1].dashoffset, -(c / 2));
  assert.equal(arcs[1].dasharray, `${c / 2} ${c / 2}`);
});

test("donutArcs: a 0% option draws a zero-length arc, not NaN", () => {
  const arcs = donutArcs([100, 0], 10);
  assert.match(arcs[1].dasharray, /^0 /);
});
