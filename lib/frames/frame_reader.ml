open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Binary_packing


module Frame = Frame_piqi
type t = Trace.Reader.t

type field =
  | Magic
  | Version
  | Bfd_arch
  | Bfd_mach
  | Frames
  | Toc
  [@@deriving enum, variants]

type header = {
  magic : int64;
  version : int;
  bfd_arch : Bfd.Arch.t;
  bfd_mach : int;
  frames : int64;
  toc_off : int64;
}

type frame = Frame.frame

type chan = {
  piqi : Piqirun.t;
  close : unit -> unit;
  skip_field : unit -> unit;
}

type reader = {
  header : header;
  meta : dict;
  chan : chan;
  frames : unit -> frame option;
}


(** Map BFD architecture specification to BAP architecture.

    Note: it looks like that having BFD Arch and Machine
    specifications is not enough, and some information is missing in the
    trace header, in particular we need endianness information.
*)
module Arch = struct
  let arm n = Bfd.Mach.Arm.(match of_enum n with
      | Some V4 -> Some `armv4
      | Some V4T -> Some `thumbv4
      | Some V5 -> Some `armv5
      | Some (V5T | V5TE | XScale) -> Some `thumbv5
      | Some Unknown -> Some `armv7
      | Some _ -> None
      | None -> None)

  let mips n = Bfd.Mach.Mips.(match of_enum n with
      | Some (Isa32 | Isa32r2) -> Some `mips
      | Some (Isa64 | Isa64r2) -> Some `mips64
      | None -> None)

  let ppc n = Bfd.Mach.Ppc.(match of_enum n with
      | Some Ppc32 -> Some `ppc
      | Some Ppc64 -> Some `ppc64
      | _ -> None)

  let sparc n = Bfd.Mach.Sparc.(match of_enum n with
      | Some Sparc -> Some `sparc
      | Some (V9 | V9a | V9b) -> Some `sparcv9
      | _ -> None)

  let i386 n = Bfd.Mach.I386.(match of_enum n with
      | Some (I386 | I8086 | I386_intel) -> Some `x86
      | Some (X86_64 | X86_64_intel) -> Some `x86_64
      | _ -> None)

  (** a projection from BFD architectures to BAP.  *)
  let of_bfd arch mach = match arch with
    | Bfd.Arch.Arm -> arm mach
    | Bfd.Arch.I386 -> i386 mach
    | Bfd.Arch.Mips -> mips mach
    | Bfd.Arch.Powerpc -> ppc mach
    | Bfd.Arch.Sparc -> sparc mach
    | _ -> None
end

exception Parse_error of string
let parse_error fmt =
  Format.ksprintf (fun s -> raise (Parse_error s)) fmt

let field_size = 8
let header_size = (max_field + 1) * field_size
let field_offset f = field_to_enum f * field_size
let field f unpack buf = unpack ~buf ~pos:(field_offset f)
let int = unpack_signed_64_int_little_endian
let int64 = unpack_signed_64_little_endian


let arch ~buf ~pos =
  match Bfd.Arch.of_enum (int ~buf ~pos) with
  | None -> parse_error "Unknown BFD arch id: %d" (int ~buf ~pos)
  | Some a -> a

let header buf = {
  magic    = field magic    int64    buf;
  version  = field version  int      buf;
  bfd_arch = field bfd_arch arch     buf;
  bfd_mach = field bfd_mach int      buf;
  frames   = field frames   int64    buf;
  toc_off  = field toc      int64    buf;
}

let read_header ic =
  let len = header_size in
  let buf = Bytes.create len in
  match In_channel.really_input ic ~buf ~pos:0 ~len with
  | None -> parse_error "malformed header"
  | Some () -> header buf


(** [skip_field ch] will skip the sizeof_frame field, as we don't
    need it at all, since piqi serialization can read the frame without
    knowing the size.
    We use `Caml.really_input` instead of pos/seek, as the latter will
    allocate extra int64 each time, and we're not using [In_channel]'s
    version of the really_input as it will allocate a closure every
    time. *)
let skip_field =
  let len = field_size in
  let buf = Bytes.create len in
  fun ch -> Caml.unsafe_really_input ch buf 0 len


let tracer {Frame.Tracer.name; args; version} = Tracer.{
    name; version;
    args = Array.of_list args;
  }

let binary {Frame.Target.path; args} = Binary.{
    path; args = Array.of_list args
  }

let fstats {Frame.Fstats.size; atime; mtime; ctime} = File_stats.{
    size; atime; mtime; ctime
  }

let field tag v d = Dict.set d tag v

let meta_fields meta = Frame.Meta_frame.[
    field Meta.user meta.user;
    field Meta.host meta.host;
    field Meta.tracer @@ tracer meta.tracer;
    field Meta.binary @@ binary meta.target;
    field Meta.binary_file_stats @@ fstats meta.fstats;
  ]

let meta_frame frame =
  meta_fields frame |> List.fold ~init:Dict.empty ~f:(fun d f -> f d)


let read_meta header {chan; piqi} =
  if header.version = 1 then Dict.empty
  else begin
    skip_field chan;
    match Frame.parse_frame piqi with
    | `meta_frame frame -> meta_frame frame
    | _ -> Dict.empty
  end

let read_frames {chan;piqi;skip} = fun () ->
  try
    skip_field ();
    Some (Frame.parse_frame piqi)
  with
    Piqirun.IBuf.End_of_buffer | End_of_file ->
    In_channel.close chan;
    None

let create uri =
  let ic = In_channel.create ~binary:true (Uri.path uri) in
  let close = lazy (In_channel.close ic) in
  let close () = Lazy.force close in
  let piqi = Piqirun.init_from_channel ic in
  let skip_field () = skip_field ic in
  let chan = {piqi; close; skip_field} in
  try
    let header = read_header ic in
    let meta = read_meta header chan in
    let frames = read_frames chan in
    {header;meta;frames;chan}
  with exn ->
    close ();
    raise exn

let close t = t.chan.close ()

let meta t = t.meta
let arch t = Arch.of_bfd t.header.bfd_arch t.header.bfd_mach
let next_frame t = t.frames ()
