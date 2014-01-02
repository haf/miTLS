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
val rangeSum: range -> range -> range

val ivSize: epoch -> nat
val fixedPadSize: SessionInfo -> nat
val maxPadSize: SessionInfo -> nat
val targetLength: epoch -> range -> nat
val cipherRangeClass: epoch -> nat -> range
val rangeClass: epoch -> range -> range
