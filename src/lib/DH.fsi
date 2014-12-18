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

module DH

open Bytes
open DHGroup

open CoreKeys

type secret

val leak  : dhparams -> elt -> secret -> bytes
val coerce: dhparams -> elt -> bytes -> secret

val serverGen: string -> DHDB.dhdb -> nat * nat -> DHDB.dhdb * dhparams * elt * secret
val clientGenExp: dhparams -> elt -> (elt * PMS.dhpms)
val serverExp: dhparams -> elt -> elt -> secret -> PMS.dhpms
