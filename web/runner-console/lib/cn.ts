import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge conditional class names, letting later utilities win. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Windows exit codes surface as large unsigned values in Node. Translate the
 * ones this project actually hits into a sentence, so the console reports a
 * cause instead of a number.
 */
export function explainExit(code: number | null, signal: string | null): {
  tone: "ok" | "warn" | "danger";
  label: string;
  detail: string;
} {
  if (signal) {
    return {
      tone: "warn",
      label: `stopped (${signal})`,
      detail: "The process was terminated before it finished.",
    };
  }
  if (code === null) {
    return {
      tone: "warn",
      label: "no exit code",
      detail: "The process never reported how it ended.",
    };
  }
  if (code === 0) {
    return { tone: "ok", label: "exit 0", detail: "The command reported success." };
  }

  const unsigned = code >>> 0;
  const hex = `0x${unsigned.toString(16).toUpperCase()}`;

  if (unsigned === 0xc0000135) {
    return {
      tone: "danger",
      label: `exit ${hex}`,
      detail:
        "STATUS_DLL_NOT_FOUND — a shared library this binary links is missing. For the Zarith-linked tools that is cyggmp, which is not on this host's PATH. The build and the parser tests do not need it.",
    };
  }
  if (unsigned === 0xc0000142) {
    return {
      tone: "danger",
      label: `exit ${hex}`,
      detail: "STATUS_DLL_INIT_FAILED — a library was found but could not initialise.",
    };
  }
  if (unsigned === 0xc0000005) {
    return {
      tone: "danger",
      label: `exit ${hex}`,
      detail: "STATUS_ACCESS_VIOLATION — the process crashed on an invalid memory access.",
    };
  }

  return {
    tone: "danger",
    label: `exit ${code}`,
    detail: "The command reported failure.",
  };
}

/** Format a duration the way a console should: seconds once past a minute. */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds - minutes * 60)}s`;
}
