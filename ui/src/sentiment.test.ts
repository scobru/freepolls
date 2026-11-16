import test from "node:test";
import assert from "node:assert/strict";
import { isCorrect, shares } from "./sentiment.ts";

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
