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

module Range

open Bytes
open TLSInfo

type range = nat * nat (* length range *)
type rbytes = bytes
val sum: range -> range -> range

val ivSize: id -> nat
val fixedPadSize: id -> nat
val maxPadSize: id -> nat
val alignedRange: id -> range -> range
val targetLength: id -> range -> nat
val cipherRangeClass: id -> nat -> range
val rangeClass: id -> range -> range
