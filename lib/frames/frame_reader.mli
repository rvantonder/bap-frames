open Bap.Std
open Frame_piqi

type t


exception Parse_error of string


val create : Uri.t -> t

val meta : t -> dict

val version : t -> int

val arch : t -> arch option

val next_frame : t -> frame option
