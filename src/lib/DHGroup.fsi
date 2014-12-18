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

module DHGroup

open Bytes

type p   = bytes
type q   = bytes
type elt = bytes
type g   = elt

type preds = Elt of p * g * bytes

val genElement: p -> g -> option<q> -> elt
val checkElement: p -> g -> bytes -> option<elt>
val dhparams: p -> g -> option<q> -> CoreKeys.dhparams
