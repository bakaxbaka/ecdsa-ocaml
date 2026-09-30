import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    "next-env.d.ts",
    // Parked, not dead. The command-runner console needs a live Node process
    // and therefore its own server-mode Next app; this one is a static export
    // the OCaml engine serves. See web/runner-console/README.md.
    "runner-console/**",
  ]),
]);

export default eslintConfig;
