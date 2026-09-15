(* lib/common/common.ml
   Entry point for the Common library.
   Re-exports the four error families so external code can write
   [Common.Parse_error.t] instead of [Common__Error.Parse_error.t]. *)

module Parse_error     = Error.Parse_error
module Der_error       = Error.Der_error
module Signature_error = Error.Signature_error
module Recovery_error  = Error.Recovery_error
