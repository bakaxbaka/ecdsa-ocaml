import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Count what the user will actually see, so the UI can assert completeness.
 *
 * These are used by the results console to compare a declared count against a
 * rendered count. If they ever disagree, the console says so in red rather than
 * quietly showing a partial value.
 */
export function countDeep(value: unknown): number {
  if (value === null || value === undefined) return 1;
  if (Array.isArray(value)) return value.reduce<number>((a, v) => a + countDeep(v), 1);
  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>).reduce<number>(
      (a, v) => a + countDeep(v),
      1,
    );
  }
  return 1;
}

/** Exact character length of the raw JSON, not the rendered DOM. */
export function exactLength(value: unknown): number {
  return JSON.stringify(value)?.length ?? 0;
}

export function exactBytes(value: unknown): number {
  const s = JSON.stringify(value) ?? "";
  return new TextEncoder().encode(s).length;
}

export function formatDuration(ms: number): string {
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(2)} MiB`;
}
