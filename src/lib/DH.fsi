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

module DH

open Bytes
open DHGroup

type secret

//Restricting the interface to the minimum
//val gen_pp     : unit -> p * g * (option<q>)
//val default_pp : unit -> p * g * (option<q>)

//val genKey: p -> g -> option<q> -> elt * secret
//val exp: p -> g -> elt -> elt -> secret -> PMS.dhpms

val serverGen: unit -> p * g * elt * secret
val clientGenExp: p -> g -> elt -> (elt * secret * PMS.dhpms)
val serverExp: p -> g -> elt -> elt -> secret -> PMS.dhpms
