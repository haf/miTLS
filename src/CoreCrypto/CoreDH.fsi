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

module CoreDH
open Bytes
open CoreKeys

(* ------------------------------------------------------------------------ *)
type skey = dhskey
type pkey = dhpkey

(* ------------------------------------------------------------------------ *)
val check_element: bytes -> bytes -> bool
val gen_params : unit -> CoreKeys.dhparams
val gen_key    : dhparams -> skey * pkey
val agreement  : dhparams -> dhsbytes -> dhpbytes -> bytes

(* ------------------------------------------------------------------------ *)
val save_params_to_file   : string -> dhparams -> bool
val load_params_from_file : string -> dhparams option
val load_default_params   : unit -> dhparams
