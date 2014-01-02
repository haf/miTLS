(*
 * Copyright (c) 2012--2013 MSR-INRIA Joint Center. All rights reserved.
 * 
 * This code is distributed under the terms for the CeCILL-B (version 1)
 * license.
 * 
 * You should have received a copy of the CeCILL-B (version 1) license
 * along with this program.  If not, see:
 * 
 *   http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.txt
 *)

module Bytes

type nat = int
type cbytes = byte[]
[<NoComparison>]
type bytes
type lbytes = bytes
val empty_bytes: bytes
val abytes: byte[] -> bytes
val abyte: byte -> bytes
val abyte2: byte * byte -> bytes
val cbytes: bytes -> byte[]
val cbyte: bytes -> byte
val cbyte2: bytes -> byte * byte

val createBytes: int -> int -> bytes

val bytes_of_int: int -> int -> bytes

val int_of_bytes: bytes -> int

val length: bytes -> int

val equalBytes: bytes -> bytes -> bool
val xor: bytes -> bytes -> int -> bytes

(* append *)
val (@|): bytes -> bytes -> bytes
val split: bytes -> int -> (bytes * bytes)
val split2: bytes -> int -> int -> (bytes * bytes * bytes)
(* strings *)
val utf8: string -> bytes
val iutf8: bytes -> string

val todo: string -> unit
