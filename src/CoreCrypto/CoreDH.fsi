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

module CoreDH

open Bytes
open Error
open CoreKeys
open DHDB

(* ------------------------------------------------------------------------ *)
val check_params : dhdb -> nat * nat -> bytes -> bytes -> (string,dhdb*dhparams) optResult
val check_element: dhparams -> bytes -> bool
val gen_key      : dhparams -> dhskey * dhpkey
// less efficient implementation, in case q is not available
val gen_key_pg   : bytes -> bytes -> dhskey * dhpkey
val agreement    : bytes -> dhskey -> dhpkey -> bytes

(* ------------------------------------------------------------------------ *)
// Throws exceptions in case of error
// (file not found, parsing error, unsafe parameters...)
val load_default_params   : string -> dhdb -> nat * nat -> dhdb*dhparams
