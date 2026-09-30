/**
 * The capability surface, read from the project's own source.
 *
 * This exists so the UI can show what the engine really offers without anyone
 * hand-copying a list that then drifts. The route list is parsed out of
 * `lib/api/endpoints.ml` at request time, and the command list comes from the
 * same catalog the runner enforces.
 *
 * Read-only: it opens files and returns JSON. It runs nothing.
 */

import fs from "node:fs/promises";
import path from "node:path";

import { COMMANDS } from "@/lib/commands/catalog";
import { repoRoot } from "@/lib/commands/runner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface Surface {
  ok: true;
  project: string;
  engine: {
    sourceFile: string;
    routes: string[];
    note: string;
  };
  runner: {
    commands: {
      id: string;
      group: string;
      label: string;
      dune: string[];
      knownIssue: string | null;
    }[];
    note: string;
  };
  absent: string[];
}

/**
 * Pull the route strings out of the `let routes : string list = [ ... ]` block.
 * Deliberately narrow: it reads one known declaration rather than trying to
 * parse OCaml, and it returns the strings verbatim so the UI cannot invent one.
 */
async function readRoutes(file: string): Promise<string[]> {
  const text = await fs.readFile(file, "utf8");
  const marker = "let routes";
  const start = text.indexOf(marker);
  if (start === -1) return [];
  const open = text.indexOf("[", start);
  const close = text.indexOf("]", open);
  if (open === -1 || close === -1) return [];

  const body = text.slice(open, close);
  return [...body.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

export async function GET() {
  const root = repoRoot();
  const engineFile = path.join(root, "lib", "api", "endpoints.ml");

  let routes: string[] = [];
  let readError: string | null = null;
  try {
    routes = await readRoutes(engineFile);
  } catch (err) {
    readError = err instanceof Error ? err.message : String(err);
  }

  const payload: Surface = {
    ok: true,
    project: root,
    engine: {
      sourceFile: "lib/api/endpoints.ml",
      routes,
      note: readError
        ? `The route list could not be read from ${engineFile}: ${readError}`
        : `${routes.length} routes, read from the handler dispatch in lib/api/endpoints.ml. On this host bin/server.exe cannot start (it aborts with 0xC0000135 because cyggmp is missing), so these routes are listed as source truth, not as a live service.`,
    },
    runner: {
      commands: COMMANDS.map((c) => ({
        id: c.id,
        group: c.group,
        label: c.label,
        dune: c.dune,
        knownIssue: c.knownIssue ?? null,
      })),
      note: "These are the only commands the runner will execute. Anything else is refused before a process is created.",
    },
    absent: [
      "Dream / Lwt — no async web framework is in the dependency set",
      "Executor module — no create/eval/launch_file/run_script/kill/list_sessions/get_session/close_session",
      "session, session_id, execution_id on the wire",
      "exec_status (Queued | Running | Completed | Failed | Timed_out | Killed)",
      "value_kind (Int | Float | String | Bool | List | Record | Unit | Opaque)",
      "execution_result { id; session_id; status; source; stdout; stderr; value; duration_ms; started_at; finished_at }",
      "Handlers.Session.* / Handlers.Exec.* / Handlers.File.* / Handlers.Ws.*",
      "WebSocket endpoint (GET /api/ws/session/:id)",
      "File CRUD routes (GET /api/files, PUT /api/files/*)",
      "Authentication, rate limiting, per-execution temp directories",
      "Melange / TyXML / Bonsai frontend",
    ].map((s) => s),
  };

  return Response.json(payload, { headers: { "cache-control": "no-store" } });
}
