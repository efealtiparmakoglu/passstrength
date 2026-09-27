import assert from "node:assert/strict";
import { test } from "node:test";

import { ATTACK_RATES, charsetEntropy, estimateCrackSeconds, humanizeSeconds, scorePassword } from "../src/scoring.ts";
import { renderText } from "../src/cli.ts";

test("empty password is the weakest possible", () => {
  const r = scorePassword("");
  assert.equal(r.score, 0);
  assert.equal(r.label, "very weak");
  assert.deepEqual(r.warnings, ["empty password"]);
});

test("classic bad passwords score 0", () => {
  for (const pw of ["password", "123456", "qwerty", "letmein", "admin", "monkey"]) {
    const r = scorePassword(pw);
    assert.equal(r.score, 0, `${pw} scored ${r.score}`);
  }
});

test("long random passphrase scores highest", () => {
  const r = scorePassword("correct horse battery staple lantern");
  assert.equal(r.score, 4, "passphrase should be very strong");
  assert.ok(r.crackSeconds.offlineFastHash > 1e6);
});

test("dictionary words inside a longer password are flagged", () => {
  const r = scorePassword("summer2024");
  const kinds = r.patterns.map((p) => p.kind);
  assert.ok(kinds.includes("year"), `expected year pattern, got ${kinds}`);
  assert.ok(r.warnings.some((w) => w.includes("date")), "expected a date warning");
});

test("keyboard runs are detected forward and reversed", () => {
  const forward = scorePassword("qwertyuiop");
  const reversed = scorePassword("poiuytrewq");
  assert.ok(forward.patterns.some((p) => p.kind === "keyboard"));
  assert.ok(reversed.patterns.some((p) => p.kind === "keyboard"));
});

test("repeats and sequences are detected", () => {
  const repeat = scorePassword("aaaaaaaaaaaa");
  assert.ok(repeat.patterns.some((p) => p.kind === "repeat"));
  const seq = scorePassword("123456789");
  assert.ok(seq.patterns.some((p) => p.kind === "sequence"));
});

test("leetspeak dictionary words are recognized", () => {
  const r = scorePassword("p4ssw0rd");
  assert.ok(r.patterns.some((p) => p.kind.startsWith("dictionary")),
    `expected dictionary pattern, got ${r.patterns.map((p) => p.kind)}`);
});

test("longer is monotonically harder", () => {
  const short = scorePassword("Xk9!mQ");
  const longer = scorePassword("Xk9!mQp2#Lv");
  assert.ok(longer.crackSeconds.offlineFastHash > short.crackSeconds.offlineFastHash);
});

test("charset entropy reflects the alphabet used", () => {
  const lower = charsetEntropy("abcdefgh");
  assert.equal(lower.size, 26);
  assert.ok(Math.abs(lower.bitsPerChar - Math.log2(26)) < 1e-9);

  const mixed = charsetEntropy("abcdefgh123!@#");
  assert.equal(mixed.size, 26 + 10 + 33);
  assert.ok(mixed.bitsPerChar > lower.bitsPerChar);

  assert.equal(charsetEntropy("").size, 1); // never divide by zero
});

test("crack time = guesses / rate", () => {
  assert.equal(estimateCrackSeconds(1000, 10), 100);
  assert.equal(estimateCrackSeconds(guesses_hash(), ATTACK_RATES.offlineFastHash) > 0, true);
});

function guesses_hash() {
  return 1e10;
}

test("humanize covers the whole time range", () => {
  assert.equal(humanizeSeconds(0.2), "instantly");
  assert.equal(humanizeSeconds(30), "30 seconds");
  assert.equal(humanizeSeconds(120), "2 minutes");
  assert.equal(humanizeSeconds(7200), "2 hours");
  assert.equal(humanizeSeconds(86400 * 3), "3 days");
  assert.equal(humanizeSeconds(86400 * 365 * 2), "2 years");
  assert.equal(humanizeSeconds(86400 * 365 * 500), "centuries");
});

test("suggestions are always present", () => {
  const weak = scorePassword("abc");
  assert.ok(weak.suggestions.length > 0);
  const strong = scorePassword("correct horse battery staple");
  assert.equal(strong.suggestions[0], "good — store it in a password manager and never reuse it");
});

test("rendering includes bar, times and next steps", () => {
  const r = scorePassword("hunter2");
  const text = renderText(r, "hunter2");
  assert.match(text, /(very weak|weak|fair|strong|very strong)/i);
  assert.match(text, /length\s+7/);
  assert.match(text, /offline, GPU vs fast hash/);
  assert.match(text, /next steps:/);
});

test("score never goes out of range", () => {
  for (const pw of ["", "a", "short", "Passw0rd!", "x".repeat(40), "correct horse battery staple"]) {
    const r = scorePassword(pw);
    assert.ok(r.score >= 0 && r.score <= 4, `${pw} -> ${r.score}`);
  }
});
