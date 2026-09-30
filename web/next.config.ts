import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /**
   * Static export, served by the OCaml analysis server itself.
   *
   * `bin/server.ml` serves this build from `web/out` on 127.0.0.1:8787 and
   * answers `POST /api/*` from the same origin. One process, one origin, no
   * CORS and no second runtime — which is why the client in `src/lib/api.ts`
   * uses relative paths and needs no base URL.
   *
   * This must stay a static export. `output` is not a styling choice here: the
   * whole frontend is a folder of files the engine hands back, and switching it
   * to server mode would leave the engine with nothing to serve.
   */
  output: "export",

  /** Emit `out/route/index.html` rather than `out/route.html`. */
  trailingSlash: true,

  images: { unoptimized: true },
};

export default nextConfig;
