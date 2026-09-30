(* bin/server.ml
   The console's compute server.

   Hand-rolled HTTP/1.1 rather than cohttp: this Windows switch has no HTTP
   library installed, and `unix` is already available.  The server is
   localhost-only and both ends of the wire are ours, so a small, explicit
   implementation is a better trade than an opam install that may not build.

   {1 No truncation}

   Responses are written whole.  The body is serialised once into a single
   string and written with a Content-Length header; nothing is chunked away,
   capped, or silently shortened.  Oversized results are sent as-is. *)

let host = "127.0.0.1"

(* Port is overridable so several instances can coexist; 8787 is the default the
   frontend expects. *)
let port =
  match Sys.getenv_opt "ECDSAC_ANALYZER_PORT" with
  | Some s -> (match int_of_string_opt (String.trim s) with Some p -> p | None -> 8787)
  | None -> 8787

let root =
  match Sys.getenv_opt "ECDSAC_ANALYZER_ROOT" with
  | Some s when String.trim s <> "" -> String.trim s
  | _ -> Sys.getcwd ()

let now () = Unix.gettimeofday ()

(* ------------------------------------------------------------------ http *)

let read_until_headers ic =
  (* Read the request head, up to and including the blank line. *)
  let buf = Buffer.create 512 in
  let rec loop () =
    match input_line ic with
    | exception End_of_file -> Buffer.contents buf
    | line ->
      let line = if String.length line > 0 && line.[String.length line - 1] = '\r'
                 then String.sub line 0 (String.length line - 1) else line in
      if line = "" then Buffer.contents buf
      else begin
        Buffer.add_string buf line;
        Buffer.add_char buf '\n';
        loop ()
      end
  in
  loop ()

let split_lines s =
  String.split_on_char '\n' s
  |> List.filter (fun l -> String.trim l <> "")

let header_value (headers : (string * string) list) (name : string) : string option =
  let lname = String.lowercase_ascii name in
  List.find_map
    (fun (k, v) -> if String.lowercase_ascii k = lname then Some v else None)
    headers

(* Write a complete response.  Content-Length is always exact, so a client can
   verify it received the whole body. *)
let write_response oc ~status ~content_type (body : string) =
  let status_text =
    match status with
    | 200 -> "OK"
    | 204 -> "No Content"
    | 400 -> "Bad Request"
    | 404 -> "Not Found"
    | 405 -> "Method Not Allowed"
    | 413 -> "Payload Too Large"
    | _ -> "Internal Server Error"
  in
  Printf.fprintf oc "HTTP/1.1 %d %s\r\n" status status_text;
  Printf.fprintf oc "Content-Type: %s\r\n" content_type;
  Printf.fprintf oc "Content-Length: %d\r\n" (String.length body);
  (* The UI runs on a different port in dev, so allow it.  Localhost only. *)
  Printf.fprintf oc "Access-Control-Allow-Origin: *\r\n";
  Printf.fprintf oc "Access-Control-Allow-Headers: content-type\r\n";
  Printf.fprintf oc "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
  Printf.fprintf oc "Cache-Control: no-store\r\n";
  Printf.fprintf oc "Connection: close\r\n";
  Printf.fprintf oc "\r\n";
  output_string oc body;
  flush oc

(* ------------------------------------------------------------------ static files *)

let content_type_of path =
  let lower = String.lowercase_ascii path in
  let ends s = Filename.check_suffix lower s in
  if ends ".html" then "text/html; charset=utf-8"
  else if ends ".css" then "text/css; charset=utf-8"
  else if ends ".js" then "application/javascript; charset=utf-8"
  else if ends ".json" then "application/json; charset=utf-8"
  else if ends ".svg" then "image/svg+xml"
  else if ends ".png" then "image/png"
  else if ends ".ico" then "image/x-icon"
  else "application/octet-stream"

(* Refuse to leave the served directory.  A request path is normalised and any
   ".." segment is rejected outright rather than being cleverly resolved. *)
let is_safe_relpath (p : string) : bool =
  let parts = String.split_on_char '/' p in
  List.for_all (fun seg -> seg <> ".." && seg <> "." && seg <> "") parts
  && not (String.contains p '\\')
  && not (String.contains p ':')

(* The file a request path names.  "/" is "index.html"; everything else is the
   path without its leading slash.  Shared so that the Content-Type is derived
   from the same name the file was opened under. *)
let resolved_relpath (path : string) : string =
  if path = "/" || path = "" then "index.html"
  else if String.length path > 1 && path.[0] = '/' then
    String.sub path 1 (String.length path - 1)
  else path

let serve_static ~dir (path : string) : string option =
  let rel = resolved_relpath path in
  if not (is_safe_relpath rel) then None
  else
    let full = Filename.concat dir rel in
    if Sys.file_exists full && not (Sys.is_directory full) then begin
      let ic = open_in_bin full in
      let n = in_channel_length ic in
      let s = really_input_string ic n in
      close_in ic;
      Some s
    end else None

(* ------------------------------------------------------------------ dispatch *)

let handle_client ~static_dir (ic : in_channel) (oc : out_channel) =
  let head = read_until_headers ic in
  if String.trim head = "" then ()
  else begin
    let lines = split_lines head in
    match lines with
    | [] -> ()
    | request_line :: header_lines ->
      let headers =
        List.filter_map
          (fun l ->
             match String.index_opt l ':' with
             | None -> None
             | Some i ->
               let k = String.trim (String.sub l 0 i) in
               let v = String.trim (String.sub l (i + 1) (String.length l - i - 1)) in
               Some (k, v))
          header_lines
      in
      (* METHOD /path HTTP/1.1 *)
      let parts = String.split_on_char ' ' (String.trim request_line) in
      let method_ = match parts with m :: _ -> m | [] -> "" in
      let path = match parts with _ :: p :: _ -> p | _ -> "/" in
      (* Strip a query string; routes are matched on path alone. *)
      let path =
        match String.index_opt path '?' with
        | Some i -> String.sub path 0 i
        | None -> path
      in

      let content_length =
        match header_value headers "content-length" with
        | Some v -> (match int_of_string_opt (String.trim v) with Some n -> n | None -> 0)
        | None -> 0
      in
      let body_text =
        if content_length > 0 then really_input_string ic content_length else ""
      in

      if method_ = "OPTIONS" then
        write_response oc ~status:204 ~content_type:"text/plain"
          ""
      else if String.length path >= 5 && String.sub path 0 5 = "/api/" then begin
        ignore body_text;
        let json_body =
          if body_text = "" then Json.Null
          else
            match Json.parse body_text with
            | Ok v -> v
            | Error m ->
              Json.Obj
                [ "kind", Json.Str "invalid_json";
                  "message", Json.Str m;
                  "received_length", Json.Int (String.length body_text) ]
        in
        let route = method_ ^ " " ^ path in
        let resp = Endpoints.handle ~root ~now route json_body in
        let serialized = Json.to_string resp.Endpoints.body in
        write_response oc ~status:resp.Endpoints.status
          ~content_type:resp.Endpoints.content_type serialized
      end
      else begin
        (* Not an API route: serve the built frontend, if one exists. *)
        match static_dir with
        | Some dir ->
          (match serve_static ~dir path with
           | Some content ->
             (* The Content-Type must come from the file that was actually
                resolved, not from the request path.  Requesting "/" resolves to
                "index.html", but "/" itself has no suffix, so asking
                [content_type_of path] returned application/octet-stream and the
                browser downloaded the interface instead of rendering it. *)
             write_response oc ~status:200
               ~content_type:(content_type_of (resolved_relpath path)) content
           | None ->
             (* SPA fallback: hand back index.html for unknown non-file paths. *)
             (match serve_static ~dir "index.html" with
              | Some content ->
                write_response oc ~status:200
                  ~content_type:"text/html; charset=utf-8" content
              | None ->
                write_response oc ~status:404 ~content_type:"text/plain; charset=utf-8"
                  "not found\n"))
        | None ->
          let routes = String.concat "\n  " Endpoints.routes in
          write_response oc ~status:404 ~content_type:"text/plain; charset=utf-8"
            (Printf.sprintf
               "ecdsa-ocaml analysis server\n\nNo frontend build was found.\nTry one of:\n  %s\n\nThe full route list is also at GET /api/functions after a frontend build,\nor via POST on the routes above.\n" routes)
      end
  end

(* ------------------------------------------------------------------ main *)

let find_static_dir () =
  let candidates =
    [ Filename.concat root "web/out";
      Filename.concat root "web/.next/standalone/web/out";
      Filename.concat root "web/dist";
      Filename.concat root "web/build" ]
  in
  List.find_opt (fun d -> Sys.file_exists d && Sys.is_directory d) candidates

let () =
  let addr = Unix.inet_addr_of_string host in
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  (* SO_REUSEADDR so a restart does not fail on a lingering socket. *)
  Unix.setsockopt sock Unix.SO_REUSEADDR true;
  Unix.bind sock (Unix.ADDR_INET (addr, port));
  Unix.listen sock 64;

  let static_dir = find_static_dir () in

  Printf.printf "ecdsa-ocaml analysis server\n";
  Printf.printf "  listening   http://%s:%d\n" host port;
  Printf.printf "  root        %s\n" root;
  Printf.printf "  routes      %d\n" (List.length Endpoints.routes);
  (match static_dir with
   | Some d -> Printf.printf "  frontend    %s\n" d
   | None -> Printf.printf "  frontend    (none built; API only)\n");
  flush stdout;

  let running = ref true in
  (* Ctrl+C should stop the accept loop cleanly rather than leaving the port
     bound. *)
  Sys.set_signal Sys.sigint (Sys.Signal_handle (fun _ -> running := false));
  (try Sys.set_signal Sys.sigterm (Sys.Signal_handle (fun _ -> running := false))
   with _ -> ());

  while !running do
    match Unix.accept sock with
    | (fd, _addr) ->
      (* Sequential handling.  One local console does not need concurrency, and
         a single-threaded loop removes a whole class of races.  A slow request
         blocks only the next request, which is acceptable here. *)
      (try
         let ic = Unix.in_channel_of_descr fd in
         let oc = Unix.out_channel_of_descr fd in
         handle_client ~static_dir ic oc
       with e ->
         (* A malformed request must not take the server down. *)
         (try
            let oc = Unix.out_channel_of_descr fd in
            write_response oc ~status:400 ~content_type:"application/json; charset=utf-8"
              (Json.to_string
                 (Json.Obj
                    [ "kind", Json.Str "request_error";
                      "message", Json.Str (Printexc.to_string e) ]))
          with _ -> ()));
      (try Unix.close fd with _ -> ())
    | exception Unix.Unix_error (Unix.EINTR, _, _) -> ()
    | exception e ->
      Printf.eprintf "accept failed: %s\n" (Printexc.to_string e);
      flush stderr
  done;

  Printf.printf "\nshutting down\n%!";
  (try Unix.close sock with _ -> ())
