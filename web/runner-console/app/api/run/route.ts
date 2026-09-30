/**
 * The execution endpoint.
 *
 * POST { commandId, values } → an SSE stream of the process's output.
 *
 * This route is a shell, and it is built to be a narrow one:
 *  - The command comes from the catalog by id. An unknown id is rejected.
 *  - Values are validated per argument kind by the runner before any spawn.
 *  - Nothing is passed through a shell (`shell: false`), so a value can never
 *    become a second command.
 *  - The working directory is the repository root; path arguments cannot escape.
 *
 * Preconditions for deploying this beyond localhost are stated in the README:
 * it has no authentication, so it belongs on the loopback interface only.
 */

import type { NextRequest } from "next/server";

import { runStream } from "@/lib/commands/runner";
import { ValidationError } from "@/lib/commands/runner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface RunBody {
  commandId?: unknown;
  values?: unknown;
}

export async function POST(request: NextRequest) {
  let body: RunBody;
  try {
    body = (await request.json()) as RunBody;
  } catch {
    return Response.json(
      { kind: "bad_request", message: "The request body must be JSON." },
      { status: 400 },
    );
  }

  if (typeof body.commandId !== "string") {
    return Response.json(
      { kind: "bad_request", message: "A string \"commandId\" is required." },
      { status: 400 },
    );
  }

  const rawValues = body.values ?? {};
  if (typeof rawValues !== "object" || rawValues === null || Array.isArray(rawValues)) {
    return Response.json(
      { kind: "bad_request", message: "\"values\" must be an object." },
      { status: 400 },
    );
  }

  const values = rawValues as Record<string, unknown>;

  // Validate once, up front, so a schema mistake produces a clean 400 rather
  // than a half-sent stream that then fails.
  let stream: AsyncGenerator<unknown>;
  try {
    stream = runStream(body.commandId, values, request.signal) as AsyncGenerator<unknown>;
  } catch (err) {
    if (err instanceof ValidationError) {
      return Response.json({ kind: "invalid_arguments", message: err.message }, { status: 400 });
    }
    return Response.json(
      {
        kind: "spawn_failed",
        message: err instanceof Error ? err.message : String(err),
      },
      { status: 500 },
    );
  }

  const encoder = new TextEncoder();

  const readable = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (payload: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(payload)}\n\n`));
      };

      try {
        for await (const chunk of stream) {
          send(chunk);
        }
      } catch (err) {
        send({
          kind: "stderr",
          text: `The stream ended abnormally: ${err instanceof Error ? err.message : String(err)}\n`,
        });
        send({ kind: "exit", code: null, signal: null, ms: 0 });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(readable, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
