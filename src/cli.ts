/* cli.ts — passstrength command line. */
import { humanizeSeconds, scorePassword, type Score } from "./scoring.ts";
import { readFileSync } from "node:fs";

export const VERSION = "1.0.0";

const usage = `passstrength ${VERSION} — offline password strength checker (nothing leaves this machine)

usage:
  passstrength                     read a password from stdin (or prompt)
  passstrength <password>          score a password given as an argument
  passstrength --file <path>       score the first line of a file
  passstrength --json              machine-readable report
  passstrength -h | --help

warning: passing a password as a shell argument exposes it in shell history
and the process list. Prefer stdin or --file.`;

function renderBar(score: number): string {
  const filled = "█".repeat(score + 1);
  const empty = "░".repeat(4 - score);
  return `${filled}${empty}`;
}

export function renderText(result: Score, password: string): string {
  const lines: string[] = [];
  lines.push(`${renderBar(result.score)}  ${result.label.toUpperCase()}`);
  lines.push(`length      ${password.length} characters`);
  lines.push(`model       ~${result.guesses.toExponential(2)} guesses (${result.entropyBits.toFixed(1)} bits)`);
  lines.push("");
  lines.push("crack time at:");
  lines.push(`  online, throttled (100/hr):      ${humanizeSeconds(result.crackSeconds.onlineThrottled)}`);
  lines.push(`  online, unthrottled (10k/hr):    ${humanizeSeconds(result.crackSeconds.onlineUnthrottled)}`);
  lines.push(`  offline, bcrypt (10k/s):         ${humanizeSeconds(result.crackSeconds.offlineSlowHash)}`);
  lines.push(`  offline, GPU vs fast hash:       ${humanizeSeconds(result.crackSeconds.offlineFastHash)}`);
  if (result.patterns.length > 0) {
    lines.push("");
    lines.push("patterns:");
    for (const p of result.patterns) lines.push(`  [${p.kind}] ${p.note}`);
  }
  if (result.warnings.length > 0) {
    lines.push("");
    lines.push("warnings:");
    for (const w of result.warnings) lines.push(`  ! ${w}`);
  }
  lines.push("");
  lines.push("next steps:");
  for (const s of result.suggestions) lines.push(`  - ${s}`);
  return lines.join("\n");
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

export async function run(args: string[]): Promise<number> {
  if (args.includes("-h") || args.includes("--help")) {
    console.error(usage);
    return 2;
  }
  const asJson = args.includes("--json");
  const fileIndex = args.indexOf("--file");
  let password: string;

  if (fileIndex >= 0 && args[fileIndex + 1]) {
    password = readFileSync(args[fileIndex + 1], "utf8").split(/\r?\n/)[0];
  } else {
    const positional = args.filter((a) => !a.startsWith("--"));
    if (positional.length > 0) {
      password = positional[0];
    } else {
      if (process.stdin.isTTY) {
        console.error(usage);
        return 2;
      }
      password = await readStdin();
    }
  }

  const result = scorePassword(password);
  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(renderText(result, password));
  }
  return 0;
}

if (import.meta.main) {
  process.exit(await run(process.argv.slice(2)));
}
