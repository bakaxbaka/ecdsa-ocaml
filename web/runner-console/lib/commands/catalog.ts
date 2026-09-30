/**
 * The command catalog.
 *
 * Every runnable action is declared here with an explicit argument schema. The
 * runner validates against that schema before spawning anything, so the console
 * cannot be talked into running an arbitrary command line.
 *
 * Two facts about this host shaped the catalog and are recorded rather than
 * papered over:
 *
 *  1. `opam exec` is broken here — it fails with a cygwin "Exec format error"
 *     before reaching any project binary. `dune` itself is on PATH and works, so
 *     commands invoke `dune` directly.
 *  2. Most compiled binaries in this tree link Zarith, which needs cyggmp, which
 *     is not on this host's PATH. They therefore die with 0xC0000135
 *     (STATUS_DLL_NOT_FOUND) instead of running. Those commands are still
 *     listed, because hiding them would misrepresent the project, but they
 *     carry a `knownHostIssue` note so the operator sees the real cause.
 */

export interface ArgSpec {
  name: string;
  label: string;
  kind: "hex" | "integer" | "choice" | "repo-path" | "text" | "lines";
  help: string;
  required: boolean;
  options?: readonly string[];
  pattern?: RegExp;
  placeholder?: string;
  /** Delivered on stdin instead of argv — free text can never reach the argv. */
  stdin?: boolean;
}

export interface CommandSpec {
  id: string;
  group: "verify" | "tools" | "console";
  label: string;
  summary: string;
  /** Extra `dune` words. The argv always starts ["dune", ...]. */
  dune: string[];
  args: ArgSpec[];
  /** True when output arrives over time and must stream. */
  streaming: boolean;
  timeoutMs: number;
  /**
   * A complete argv that replaces the derived one. Only for repository scripts
   * that are not Dune targets. Still spawned without a shell, so it remains an
   * argv array and cannot be chained.
   */
  overridesArgv?: string[];
  /** Non-null when this command cannot fully succeed here, and why. */
  knownIssue?: string;
}

export const COMMANDS: readonly CommandSpec[] = [
  {
    id: "build",
    group: "verify",
    label: "Build",
    summary:
      "Compiles every library and executable. Dune prints nothing on success — silence here is the pass signal, not a stalled process.",
    dune: ["build"],
    args: [],
    streaming: true,
    timeoutMs: 600_000,
  },
  {
    id: "typecheck",
    group: "verify",
    label: "Type-check",
    summary:
      "Resolves and type-checks the whole tree without producing final artifacts. The fast loop while editing.",
    dune: ["build", "@check"],
    args: [],
    streaming: true,
    timeoutMs: 600_000,
    knownIssue:
      "This alias compiles every executable, including three abandoned scripts under bin/ that do not build: analyse_txs.ml (Unbound module Tx_parser), analyze_nonce_attacks.ml (Unbound module Types) and compare_txs.ml (missing .cmi). Expect a non-zero exit until those are fixed or removed from bin/dune. `dune build` does not touch them and passes.",
  },
  {
    id: "runtest",
    group: "verify",
    label: "Run every test",
    summary:
      "Runs every Alcotest and QCheck suite: ECDSA types and verification, strict DER, hash256, the transaction parser, script classification, legacy SIGHASH and BIP143.",
    dune: ["runtest", "--force"],
    args: [],
    streaming: true,
    timeoutMs: 900_000,
    knownIssue:
      "Two suites — integration/test_full_pipeline and unit/analysis/test_nonce_analysis — link Zarith and abort with 0xC0000135 because cyggmp is not on this host's PATH. The run exits 1 for that reason, not because assertions failed. Every other suite passes.",
  },
  {
    id: "runtest-scope",
    group: "verify",
    label: "Run one subtree",
    summary:
      "Restricts the run to one directory of tests. Use this to get a clean pass while the two Zarith-linked suites are blocked.",
    dune: ["runtest"],
    args: [
      {
        name: "scope",
        label: "Test scope",
        kind: "choice",
        help: "A test directory that can run on this host.",
        required: true,
        options: [
          "test/unit/crypto",
          "test/unit/bitcoin",
          "test/unit/bitcoin/sighash",
          "test/property/encoding",
          "test/unit",
          "test",
        ],
      },
    ],
    streaming: true,
    timeoutMs: 600_000,
  },
  {
    id: "fmt-check",
    group: "verify",
    label: "Check formatting",
    summary:
      "Reports which files deviate from .ocamlformat and prints the diff. Changes nothing.",
    dune: ["build", "@fmt"],
    args: [],
    streaming: true,
    timeoutMs: 300_000,
  },
  {
    id: "fmt",
    group: "verify",
    label: "Apply formatting",
    summary:
      "Rewrites files in place to match .ocamlformat. This modifies the working tree.",
    dune: ["fmt"],
    args: [],
    streaming: true,
    timeoutMs: 300_000,
  },
  {
    id: "repl",
    group: "console",
    label: "Nonce REPL",
    summary:
      "Feeds raw transaction hex to bin/main.exe on stdin, one transaction per line. It answers whether each transaction's nonce is unique or repeats within the session.",
    dune: ["exec", "bin/main.exe"],
    args: [
      {
        name: "input",
        label: "Transactions",
        kind: "lines",
        help: "One raw transaction hex per line. Written to the process's stdin, then stdin is closed.",
        required: true,
        placeholder: "0200000001<full transaction hex>",
        stdin: true,
      },
    ],
    streaming: true,
    timeoutMs: 300_000,
    knownIssue:
      "bin/main.exe links Zarith and needs cyggmp, which is missing on this host, so it exits 0xC0000135 before printing its banner. The REPL reads one raw transaction hex per line and answers whether the nonce repeats; it has no command verbs.",
  },
  {
    id: "binary",
    group: "tools",
    label: "Run an analysis binary",
    summary:
      "Runs one of the project's standalone analysis tools. Each takes its input on the command line.",
    dune: ["exec"],
    args: [
      {
        name: "target",
        label: "Binary",
        kind: "choice",
        help: "Which tool to run.",
        required: true,
        options: [
          "bin/compare_txs.exe",
          "bin/extract_vectors.exe",
          "bin/tx_signature_extractor.exe",
          "bin/analyze_nonce_attacks.exe",
          "bin/analyse_txs.exe",
          "bin/test_nonce_attacks.exe",
        ],
      },
      {
        name: "hex",
        label: "Argument",
        kind: "text",
        help: "A single positional argument, passed to the tool as its own argv entry. Leave empty to see the tool's own usage text.",
        required: false,
        placeholder: "rawtx/ or a hex string",
      },
    ],
    streaming: true,
    timeoutMs: 600_000,
    knownIssue:
      "Only bin/compare_txs.exe starts on this host: it ignores its arguments, prints 'This binary is under construction' and exits 0. The other five link Zarith and abort with 0xC0000135 before reading argv.",
  },
  {
    id: "dump-rsz",
    group: "tools",
    label: "Dump r,s,z to CSV",
    summary:
      "tools/dump_rsz.ml — walks a directory of .hex transactions and writes one CSV row per signature: txid, input index, prevout, pubkey, r, s, script type, sighash byte, z. Legacy inputs get a real z; SegWit inputs leave z empty because a prevout value is required for BIP143 and a raw transaction does not carry it.",
    dune: ["exec", "tools/dump_rsz.exe"],
    args: [
      {
        name: "dir",
        label: "Input directory",
        kind: "repo-path",
        help: "Directory of .hex files, relative to the repository root. A file path is rejected by the tool itself.",
        required: true,
        placeholder: "rawtx",
      },
      {
        name: "out",
        label: "Output CSV",
        kind: "repo-path",
        help: "Where the CSV is written. This creates or overwrites a file.",
        required: true,
        placeholder: "results/rsz.csv",
      },
    ],
    streaming: true,
    timeoutMs: 1_800_000,
    knownIssue:
      "This binary links Zarith and aborts with 0xC0000135 on this host because cyggmp is missing from PATH. The source is complete and takes two positional arguments: input dir, output CSV.",
  },
  {
    id: "scan-dir",
    group: "tools",
    label: "Scan a transaction directory",
    summary:
      "tools/scan_dir.ml — parses every .hex transaction in a directory and writes per-input rows to an intermediate CSV.",
    dune: ["exec", "tools/scan_dir.exe"],
    args: [
      {
        name: "dir",
        label: "Input directory",
        kind: "repo-path",
        help: "Directory of .hex files, relative to the repository root.",
        required: true,
        placeholder: "rawtx",
      },
      {
        name: "out",
        label: "Intermediate CSV",
        kind: "repo-path",
        help: "Where the intermediate CSV is written.",
        required: true,
        placeholder: "results/scan.csv",
      },
    ],
    streaming: true,
    timeoutMs: 1_800_000,
    knownIssue:
      "Same missing-DLL problem as dump_rsz on this host. Its usage line is: scan_dir <input_dir> <intermediate.csv>.",
  },
  {
    id: "check-layering",
    group: "verify",
    label: "Check layer discipline",
    summary:
      "tools/check-layering.ps1 — verifies that each Dune library depends only on layers below it (common → crypto → bitcoin → analysis → tx_stream → application), and fails on any upward dependency.",
    dune: ["build"],
    args: [],
    streaming: true,
    timeoutMs: 300_000,
    overridesArgv: [
      "pwsh",
      "-NoProfile",
      "-File",
      "tools/check-layering.ps1",
    ],
  },
  {
    id: "check-no-truncation",
    group: "verify",
    label: "Check no value is elided",
    summary:
      "tools/check-no-truncation.mjs — fails if any UI source could clip a value: CSS ellipsis overflow, a hidden vertical cap paired with overflow clipping, shortening result data before display, or a truncate helper.",
    dune: ["build"],
    args: [],
    streaming: true,
    timeoutMs: 300_000,
    overridesArgv: ["node", "tools/check-no-truncation.mjs"],
  },
  {
    id: "doctor",
    group: "tools",
    label: "Diagnose the toolchain",
    summary:
      "Reports the Dune version, whether the project builds, and whether the Zarith-linked binaries can start on this host. Run this first when a command fails.",
    dune: ["--version"],
    args: [],
    streaming: true,
    timeoutMs: 300_000,
  },
];

export const COMMAND_BY_ID = new Map(COMMANDS.map((c) => [c.id, c]));

export const GROUPS: { id: CommandSpec["group"]; label: string; blurb: string }[] = [
  { id: "verify", label: "Verify", blurb: "build · test · format" },
  { id: "tools", label: "Tools", blurb: "standalone binaries" },
  { id: "console", label: "Console", blurb: "interactive" },
];
