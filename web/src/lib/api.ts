/**
 * The API client.
 *
 * Every call returns the server's envelope untouched — including `duration_ms`
 * and the echoed request — so the console can show what was actually sent and
 * received rather than a reformatted summary of it.
 *
 * No response is cached, sliced, or short-circuited. If the server sends it,
 * the UI receives all of it.
 */

export interface Envelope<T> {
  duration_ms: number;
  result: T;
}

export interface ApiError {
  kind: string;
  message: string;
  [k: string]: unknown;
}

export interface Decl {
  kind: "val" | "type" | "module" | "include";
  name: string;
  signature: string;
  doc: string | null;
  file: string;
  line: number;
}

export interface ModuleInfo {
  module: string;
  library: string;
  file: string;
  doc: string | null;
  decl_count: number;
  decls: Decl[];
}

export interface Catalogue {
  ok: boolean;
  modules: ModuleInfo[];
  module_count: number;
  declaration_count: number;
}

/** A big integer, always carried as exact decimal and hex strings. */
export interface ZVal {
  dec: string;
  hex: string;
  bits: number;
}

export interface ByteStr {
  hex: string;
  len: number;
}

export interface IdDerivation {
  source: string;
  value?: string;
  value_is?: string;
  txid_available?: boolean;
  note: string;
}

export interface EndpointResult {
  ok?: boolean;
  kind?: string;
  message?: string;
  txid?: string;
  id_derivation?: IdDerivation;
  [k: string]: unknown;
}

const BASE = "";

async function post<T>(route: string, body: unknown): Promise<Envelope<T>> {
  const res = await fetch(`${BASE}${route}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
    cache: "no-store",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return (await res.json()) as Envelope<T>;
}

async function get<T>(route: string): Promise<T> {
  const res = await fetch(`${BASE}${route}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as T;
}

export const api = {
  health: () => get<Record<string, unknown>>("/api/health"),
  functions: () => post<Catalogue>("/api/functions", {}),

  parse: (hex: string, txid?: string) =>
    post<EndpointResult>("/api/parse", { hex, ...(txid ? { txid } : {}) }),

  scriptClassify: (scriptPubkeyHex: string) =>
    post<EndpointResult>("/api/script/classify", { script_pubkey_hex: scriptPubkeyHex }),

  scriptParse: (scriptHex: string) =>
    post<EndpointResult>("/api/script/parse", { script_hex: scriptHex }),

  derParse: (derHex: string) => post<EndpointResult>("/api/der/parse", { der_hex: derHex }),

  sighashLegacy: (hex: string, inputIndex: number, scriptCodeHex: string, sighashType: number) =>
    post<EndpointResult>("/api/sighash/legacy", {
      hex,
      input_index: inputIndex,
      script_code_hex: scriptCodeHex,
      sighash_type: sighashType,
    }),

  sighashBip143: (
    hex: string,
    inputIndex: number,
    scriptCodeHex: string,
    value: string,
    sighashType: number,
  ) =>
    post<EndpointResult>("/api/sighash/bip143", {
      hex,
      input_index: inputIndex,
      script_code_hex: scriptCodeHex,
      value,
      sighash_type: sighashType,
    }),

  extract: (hex: string, txid?: string) =>
    post<EndpointResult>("/api/signatures/extract", { hex, ...(txid ? { txid } : {}) }),

  observation: (hex: string, txid?: string, spkHints?: string[], utxoValues?: string[]) =>
    post<EndpointResult>("/api/observation/build", {
      hex,
      ...(txid ? { txid } : {}),
      ...(spkHints?.length ? { spk_hints: spkHints } : {}),
      ...(utxoValues?.length ? { utxo_values: utxoValues } : {}),
    }),

  nonce: (hex: string, txid?: string) =>
    post<EndpointResult>("/api/nonce/analyze", { hex, ...(txid ? { txid } : {}) }),

  statistics: (hex: string, txid?: string) =>
    post<EndpointResult>("/api/statistics", { hex, ...(txid ? { txid } : {}) }),

  sigAnalysis: (hex: string, txid?: string) =>
    post<EndpointResult>("/api/sig-analysis", { hex, ...(txid ? { txid } : {}) }),

  pipeline: (hex: string, txid?: string) =>
    post<EndpointResult>("/api/pipeline", { hex, ...(txid ? { txid } : {}) }),
};

/** The endpoints the UI offers, in the order it lists them. */
export const ENDPOINTS = [
  { id: "parse", label: "Parse transaction", group: "Transaction", needs: ["hex", "txid"] },
  { id: "extract", label: "Extract signatures", group: "Transaction", needs: ["hex", "txid"] },
  {
    id: "scriptClassify",
    label: "Classify scriptPubKey",
    group: "Script",
    needs: ["script_pubkey_hex"],
  },
  { id: "scriptParse", label: "Parse script", group: "Script", needs: ["script_hex"] },
  { id: "derParse", label: "Parse DER signature", group: "Crypto", needs: ["der_hex"] },
  {
    id: "sighashLegacy",
    label: "Legacy sighash",
    group: "Sighash",
    needs: ["hex", "input_index", "script_code_hex", "sighash_type"],
  },
  {
    id: "sighashBip143",
    label: "BIP143 sighash",
    group: "Sighash",
    needs: ["hex", "input_index", "script_code_hex", "value", "sighash_type"],
  },
  {
    id: "observation",
    label: "Build observations",
    group: "Analysis",
    needs: ["hex", "txid"],
  },
  { id: "nonce", label: "Nonce analysis", group: "Analysis", needs: ["hex", "txid"] },
  { id: "statistics", label: "Statistics", group: "Analysis", needs: ["hex", "txid"] },
  { id: "sigAnalysis", label: "Signature analysis", group: "Analysis", needs: ["hex", "txid"] },
  { id: "pipeline", label: "Full pipeline", group: "Analysis", needs: ["hex", "txid"] },
] as const;

export type EndpointId = (typeof ENDPOINTS)[number]["id"];
