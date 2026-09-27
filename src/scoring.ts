/* scoring.ts — offline password strength estimation.
 *
 * The model is coverage-based (in the spirit of zxcvbn): every character
 * is either part of a known pattern — dictionary word, repeat, keyboard
 * walk, counting run, year, date — or "uncovered", and only uncovered
 * characters cost the attacker real guesses. That is why "aaaaaaaaaaaa"
 * and "summer2024" score badly while a random-looking passphrase does not.
 *
 * Educational: these are estimates, not proofs.
 */

export interface Pattern {
  kind: string;
  matched: string;
  note: string;
  start: number;
  end: number; // exclusive
}

export interface CrackTimes {
  onlineThrottled: number;  // 100 tries/hour
  onlineUnthrottled: number; // 10k tries/hour
  offlineSlowHash: number;  // bcrypt cost 10, one GPU rig
  offlineFastHash: number;  // 8x GPU rig against MD5/SHA-1 class hashes
}

export interface Score {
  score: 0 | 1 | 2 | 3 | 4;
  label: "very weak" | "weak" | "fair" | "strong" | "very strong";
  guesses: number;
  entropyBits: number;
  patterns: Pattern[];
  warnings: string[];
  crackSeconds: Record<keyof CrackTimes, number>;
  suggestions: string[];
}

export const ATTACK_RATES: CrackTimes = {
  onlineThrottled: 100 / 3600,
  onlineUnthrottled: 10_000 / 3600,
  offlineSlowHash: 1e4,
  offlineFastHash: 1e10,
};

export const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "123456789", "12345", "1234",
  "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
  "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
  "mustang", "1234567890", "michael", "654321", "superman", "iloveyou",
  "trustno1", "sunshine", "princess", "admin", "welcome", "passw0rd",
  "p@ssw0rd", "letmein1", "welcome1", "admin123", "root", "toor", "test",
  "summer", "winter", "spring", "autumn", "january", "company", "default",
]);

const KEYBOARD_ROWS = [
  "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "!@#$%^&*()",
];

const L33T: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
  "@": "a", "$": "s", "!": "i", "|": "l", "+": "t",
};

/* --- helpers --- */

function delleet(s: string): string {
  let out = "";
  for (const ch of s.toLowerCase()) out += L33T[ch] ?? ch;
  return out;
}

export function charsetEntropy(pw: string): { bitsPerChar: number; size: number } {
  let lower = 0, upper = 0, digit = 0, symbol = 0;
  for (const ch of pw) {
    if (ch >= "a" && ch <= "z") lower++;
    else if (ch >= "A" && ch <= "Z") upper++;
    else if (ch >= "0" && ch <= "9") digit++;
    else symbol++;
  }
  let size = 0;
  if (lower) size += 26;
  if (upper) size += 26;
  if (digit) size += 10;
  if (symbol) size += 33;
  if (size === 0) size = 1;
  return { bitsPerChar: Math.log2(size), size };
}

/* --- pattern detection, with spans --- */

function findAll(
  pw: string,
  source: string,
  kind: string,
  note: (m: string) => string,
): Pattern[] {
  const out: Pattern[] = [];
  const rx = new RegExp(source, "gi");
  let m: RegExpExecArray | null;
  while ((m = rx.exec(pw)) !== null) {
    if (m[0].length === 0) {
      rx.lastIndex++;
      continue;
    }
    out.push({
      kind,
      matched: m[0],
      note: note(m[0]),
      start: m.index,
      end: m.index + m[0].length,
    });
  }
  return out;
}

function detectRepeats(pw: string): Pattern[] {
  return findAll(pw, "(.)\\1{2,}", "repeat", (m) => `"${m}" repeats`);
}

function detectSequences(pw: string): Pattern[] {
  return findAll(
    pw,
    "0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defgh|efgh|fghi|ghij|hijk|9876|8765|7654|6543|5432|4321|3210|dcba|cba|zyxw",
    "sequence",
    (m) => `counting run "${m}"`,
  );
}

function detectKeyboard(pw: string): Pattern[] {
  const lower = pw.toLowerCase();
  const found: Pattern[] = [];
  for (const row of KEYBOARD_ROWS) {
    for (let len = row.length; len >= 3; len--) {
      for (let start = 0; start + len <= row.length; start++) {
        const run = row.slice(start, start + len);
        const at = lower.indexOf(run);
        if (at >= 0) {
          found.push({ kind: "keyboard", matched: run, note: `keyboard walk "${run}"`, start: at, end: at + len });
        }
        const reversed = run.split("").reverse().join("");
        const at2 = lower.indexOf(reversed);
        if (at2 >= 0) {
          found.push({
            kind: "keyboard",
            matched: reversed,
            note: `reversed keyboard walk "${reversed}"`,
            start: at2,
            end: at2 + len,
          });
        }
      }
    }
  }
  return found;
}

function detectDates(pw: string): Pattern[] {
  return [
    ...findAll(pw, "(19|20)\\d{2}", "year", (m) => `${m} is a calendar year`),
    ...findAll(pw, "\\b[0-3]?\\d[./-][01]?\\d[./-](\\d{2}|\\d{4})\\b", "date", (m) => `looks like a date: ${m}`),
  ];
}

function detectDictionary(pw: string): Pattern[] {
  const lower = pw.toLowerCase();
  const delLeet = delleet(lower);
  for (const word of COMMON_PASSWORDS) {
    if (lower === word) {
      return [{
        kind: "dictionary",
        matched: pw,
        note: `"${word}" is one of the most common passwords ever`,
        start: 0,
        end: pw.length,
      }];
    }
    if (delLeet === word) {
      return [{
        kind: "dictionary",
        matched: pw,
        note: `"${word}" written in leetspeak`,
        start: 0,
        end: pw.length,
      }];
    }
  }
  const found: Pattern[] = [];
  for (const word of COMMON_PASSWORDS) {
    if (word.length < 5) continue;
    let at = lower.indexOf(word);
    while (at >= 0) {
      found.push({
        kind: "dictionary-sub",
        matched: word,
        note: `contains the common word "${word}"`,
        start: at,
        end: at + word.length,
      });
      at = lower.indexOf(word, at + 1);
    }
  }
  return found;
}

/* --- the guess model --- */

function mergeSpans(spans: Pattern[]): { covered: number; effective: Pattern[] } {
  if (spans.length === 0) return { covered: 0, effective: [] };
  const sorted = [...spans].sort(
    (a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start),
  );
  const effective: Pattern[] = [];
  let lastEnd = -1;
  for (const span of sorted) {
    if (span.start >= lastEnd) {
      effective.push(span);
      lastEnd = span.end;
    } else if (span.end > lastEnd) {
      effective.push({ ...span, start: lastEnd, matched: span.matched.slice(lastEnd - span.start) });
      lastEnd = span.end;
    }
  }
  const covered = effective.reduce((sum, s) => sum + (s.end - s.start), 0);
  return { covered, effective };
}

function estimateGuesses(pw: string, patterns: Pattern[]): number {
  const { covered, effective } = mergeSpans(patterns);
  const uncovered = Math.max(pw.length - covered, 0);
  const charset = charsetEntropy(pw).size;

  let guesses = 1;
  for (const span of effective) {
    const length = span.end - span.start;
    switch (span.kind) {
      case "dictionary":
        guesses *= 10; // cracked in the first handful of any wordlist
        break;
      case "dictionary-sub":
        guesses *= 100 * (length + 1); // the word plus a few guesses around it
        break;
      case "repeat":
        guesses *= 100 * Math.max(length, 1); // pick the unit, then a start offset
        break;
      case "sequence":
        guesses *= 30 * length; // up or down, a handful of start points
        break;
      case "keyboard":
        guesses *= 20 * length; // a few layouts, shifted, both directions
        break;
      case "year":
        guesses *= 200 * (length + 1); // ~100 years, with day/month prefixes
        break;
      case "date":
        guesses *= 36525 * (length + 1);
        break;
      default:
        guesses *= charset ** length;
    }
  }
  guesses *= charset ** uncovered;
  return Math.max(guesses / 2, 1);
}

export function estimateCrackSeconds(guesses: number, rate: number): number {
  return guesses / rate;
}

function humanizeSeconds(seconds: number): string {
  if (seconds < 1) return "instantly";
  const units: [number, string][] = [
    [60, "seconds"], [60, "minutes"], [24, "hours"], [365, "days"], [100, "years"],
  ];
  let value = seconds;
  for (const [factor, name] of units) {
    if (value < factor) return `${Math.round(value * 10) / 10} ${name}`;
    value /= factor;
  }
  return "centuries";
}

function scoreToLabel(score: 0 | 1 | 2 | 3 | 4): Score["label"] {
  return (["very weak", "weak", "fair", "strong", "very strong"] as const)[score];
}

/* --- the main entry point --- */

export function scorePassword(pw: string): Score {
  if (!pw) {
    return {
      score: 0,
      label: "very weak",
      guesses: 1,
      entropyBits: 0,
      patterns: [],
      warnings: ["empty password"],
      crackSeconds: {
        onlineThrottled: 0, onlineUnthrottled: 0,
        offlineSlowHash: 0, offlineFastHash: 0,
      },
      suggestions: ["use a password manager and generate 4+ random words"],
    };
  }

  const patterns: Pattern[] = [
    ...detectDictionary(pw),
    ...detectRepeats(pw),
    ...detectSequences(pw),
    ...detectKeyboard(pw),
    ...detectDates(pw),
  ];
  const kinds = new Set(patterns.map((p) => p.kind));

  const guesses = estimateGuesses(pw, patterns);
  const entropyBits = Math.log2(guesses);

  let score: 0 | 1 | 2 | 3 | 4;
  if (guesses < 1e3) score = 0;
  else if (guesses < 1e6) score = 1;
  else if (guesses < 1e8) score = 2;
  else if (guesses < 1e10) score = 3;
  else score = 4;

  const warnings: string[] = [];
  const suggestions: string[] = [];
  const offlineFast = estimateCrackSeconds(guesses, ATTACK_RATES.offlineFastHash);

  /* A raw guess count flatters short passwords: eight random-looking
   * characters are still dead in seconds against a fast hash. Cap the
   * rating by how long the password actually survives offline. */
  if (offlineFast < 3600 && score > 1) score = 1;
  else if (offlineFast < 86400 * 365 && score > 2) score = 2;
  else if (offlineFast < 86400 * 365 * 100 && score > 3) score = 3;

  if (pw.length < 12) warnings.push("shorter than 12 characters");
  if (kinds.has("dictionary")) warnings.push("is a password crackers try within the first thousand guesses");
  if (kinds.has("dictionary-sub")) warnings.push("contains a word attackers try first");
  if (kinds.has("keyboard") || kinds.has("sequence")) warnings.push("contains a keyboard walk or counting run");
  if (kinds.has("year") || kinds.has("date")) warnings.push("contains a date or year — low entropy");
  if (kinds.has("repeat")) warnings.push("repeats characters or digits");
  if (offlineFast < 3600) warnings.push("falls to a GPU rig within an hour");
  if (charsetEntropy(pw).size < 40) warnings.push("uses a small character set");

  if (kinds.has("dictionary") || kinds.has("dictionary-sub")) {
    suggestions.push("replace dictionary words with unrelated words");
  }
  if (kinds.has("keyboard") || kinds.has("sequence")) suggestions.push("avoid runs on the keyboard");
  if (kinds.has("year") || kinds.has("date")) suggestions.push("drop the year or the date");
  if (kinds.has("repeat")) suggestions.push("stop repeating characters");
  if (pw.length < 16) suggestions.push("use at least 16 characters");
  if (charsetEntropy(pw).size < 40) suggestions.push("mix in symbols or use a longer passphrase");
  if (suggestions.length === 0) {
    suggestions.push("good — store it in a password manager and never reuse it");
  }

  return {
    score,
    label: scoreToLabel(score),
    guesses,
    entropyBits,
    patterns,
    warnings,
    suggestions,
    crackSeconds: {
      onlineThrottled: estimateCrackSeconds(guesses, ATTACK_RATES.onlineThrottled),
      onlineUnthrottled: estimateCrackSeconds(guesses, ATTACK_RATES.onlineUnthrottled),
      offlineSlowHash: estimateCrackSeconds(guesses, ATTACK_RATES.offlineSlowHash),
      offlineFastHash: offlineFast,
    },
  };
}

export { humanizeSeconds };
