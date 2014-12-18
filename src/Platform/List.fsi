(*
 * Copyright (c) 2012--2014 MSR-INRIA Joint Center. All rights reserved.
 * 
 * This code is distributed under the terms for the CeCILL-B (version 1)
 * license.
 * 
 * You should have received a copy of the CeCILL-B (version 1) license
 * along with this program.  If not, see:
 * 
 *   http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.txt
 *)

module List

open Bytes

val fold: (bytes -> bytes -> bytes) -> bytes -> bytes list -> bytes
val filter: ('a -> bool) -> 'a list -> 'a list
val foldBack: (bytes -> bytes -> bytes) -> bytes list -> bytes -> bytes
val exists: ('a -> bool) -> 'a list -> bool
val memr: 'a list -> 'a -> bool when 'a : equality
val choose: ('a -> 'b option) -> 'a list -> 'b list
val tryFind: ('a -> bool) -> 'a list -> 'a option
val listLength: ('a list) -> int
val listHead: ('a list) -> 'a
val find: ('a -> bool) -> 'a list -> 'a
val map: ('a -> 'b) -> 'a list -> 'b list
