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

module DH

open Bytes
open DHGroup

type secret

val gen_pp     : unit -> p * g
val default_pp : unit -> p * g

val genKey: p -> g -> elt * secret
val exp: p -> g -> elt -> elt -> secret -> PMS.dhpms
