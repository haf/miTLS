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

#light "off"

module DHGroup

open Bytes
open CoreKeys
open TLSError

type elt = bytes

#if ideal
val goodPP: dhparams -> bool
type preds = Elt of bytes * bytes * elt
#endif

val genElement  : dhparams -> elt
val checkParams : DHDB.dhdb -> nat * nat -> bytes -> bytes -> Result<(DHDB.dhdb * dhparams)>
val checkElement: dhparams -> bytes -> option<elt>

val defaultDHparams: string -> DHDB.dhdb -> nat * nat -> (DHDB.dhdb * dhparams)
