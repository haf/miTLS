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
type bytes = byte[]
type lbytes = bytes

val createBytes: int -> int -> bytes

val bytes_of_int: int -> int -> bytes

val int_of_bytes: bytes -> int

val length: bytes -> int

val equalBytes: bytes -> bytes -> bool

(* append *)
val (@|): bytes -> bytes -> bytes
val split: bytes -> int -> (bytes * bytes)
val split2: bytes -> int -> int -> (bytes * bytes * bytes)
(* strings *)
val utf8: string -> bytes
val iutf8: bytes -> string

(* Time spans *)
type DateTime
type TimeSpan
val now: unit -> DateTime
val newTimeSpan: nat -> nat -> nat -> nat -> TimeSpan
val addTimeSpan: DateTime -> TimeSpan -> DateTime
val greaterDateTime: DateTime -> DateTime -> bool

(* List operations *)

val fold: (bytes -> bytes -> bytes) -> bytes -> bytes list -> bytes
val filter: ('a -> bool) -> 'a list -> 'a list // In HS, only used with 'a = HT_type, but it's not defined here.
val foldBack: (bytes -> bytes -> bytes) -> bytes list -> bytes -> bytes
val exists: ('a -> bool) -> 'a list -> bool
val memr: 'a list -> 'a -> bool when 'a : equality
val choose: ('a -> 'b option) -> 'a list -> 'b list // Not used parametrically in HS, but types are not defined here.
val tryFind: ('a -> bool) -> 'a list -> 'a option
#if ideal

val find: ('a -> bool) -> 'a list -> 'a
//val assoc: 'a -> ('a * 'b) list -> 'b option
//val assoc2_1: ('a*'b) -> ('a * 'b *'c) list -> 'b option
#endif
val listLength: ('a list) -> int
val listHead: ('a list) -> 'a
