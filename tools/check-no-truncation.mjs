#!/usr/bin/env node
/**
 * Truncation guard.
 *
 * The console promises that no value is ever shortened for display. That promise
 * is easy to break by accident — one `text-overflow: ellipsis`, one
 * `max-height` next to `overflow: hidden`, one `.slice(0, 120)` on a result —
 * and impossible to notice by eye once it happens.
 *
 * This script fails the build on any of those patterns. It is deliberately
 * blunt: it greps rather than parsing, because a false positive that forces a
 * comment explaining an exception is cheaper than a false negative that ships a
 * silently clipped number.
 *
 * Usage: node tools/check-no-truncation.mjs
 */

import { readFileSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const SRC = join(ROOT, "web", "src");

/** Files to inspect. */
const EXTS = new Set([".tsx", ".ts", ".css"]);

const RULES = [
  {
    id: "css-ellipsis",
    // `text-overflow: ellipsis` clips a value and hides the remainder.
    test: (line) => /text-overflow\s*:\s*ellipsis/.test(line),
    why: "text-overflow: ellipsis clips data. Values must wrap, never be elided.",
  },
  {
    id: "css-clip",
    test: (line) => /overflow\s*:\s*hidden/.test(line) && /max-height/.test(line),
    why: "max-height with overflow: hidden hides the tail of a value.",
  },
  {
    id: "js-slice-on-result",
    // Slicing a string that came from a result shortens it before display.
    test: (line) =>
      /\.(slice|substring|substr)\s*\(/.test(line) &&
      /(json|result|value|hex|data|response)/i.test(line),
    why: "Slicing result data shortens a value. Render it in full.",
  },
  { id: "js-truncate-helper", test: (line) => /\btruncate\w*\s*\(/.test(line), why: "A truncate helper exists; remove it." },
  { id: "js-ellipsis-literal", test: (line) => /["'`][^"'`]*…/.test(line), why: "An ellipsis literal in a string suggests elided output." },
];

async function* walk(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === ".next") continue;
      yield* walk(full);
    } else if (EXTS.has(extname(e.name))) {
      yield full;
    }
  }
}

let violations = 0;
const files = [];
for await (const f of walk(SRC)) files.push(f);

for (const file of files) {
  const text = readFileSync(file, "utf8");
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    // Allow an explicit, justified opt-out on the same or previous line.
    if (/no-truncation-check-allow/.test(line)) return;
    if (i > 0 && /no-truncation-check-allow/.test(lines[i - 1])) return;
    for (const rule of RULES) {
      if (rule.test(line)) {
        violations++;
        const rel = file.replace(ROOT, "").replace(/^[\\/]/, "");
        console.error(`${rel}:${i + 1}  [${rule.id}]`);
        console.error(`    ${line.trim()}`);
        console.error(`    ${rule.why}`);
      }
    }
  });
}

console.log(`\nchecked ${files.length} files in web/src`);
if (violations > 0) {
  console.error(`\nFAIL: ${violations} truncation pattern(s) found.`);
  console.error("If a finding is a genuine false positive, annotate the line with");
  console.error("`no-truncation-check-allow` and say why in a comment.");
  process.exit(1);
}
console.log("PASS: no truncation patterns found.");
