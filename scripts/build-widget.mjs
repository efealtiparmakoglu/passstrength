/* build-widget.mjs — strip TypeScript types from the scoring core so the
 * browser widget can import it as plain ESM. Zero dependencies: uses the
 * Node built-in type-stripper. */
import { stripTypeScriptTypes } from "node:module";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const source = readFileSync(join(root, "src", "scoring.ts"), "utf8");
const stripped = stripTypeScriptTypes(source, { mode: "strip" });

mkdirSync(join(root, "public"), { recursive: true });
const target = join(root, "public", "scoring.js");
writeFileSync(target, `// GENERATED from src/scoring.ts by scripts/build-widget.mjs — do not edit.\n${stripped}`);
console.log(`wrote ${target} (${stripped.length} bytes)`);
