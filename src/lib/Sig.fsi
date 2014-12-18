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

module Sig

open Bytes
open TLSConstants

(* ------------------------------------------------------------------------ *)
type alg   = sigHashAlg

type text = bytes
type sigv = bytes

(* ------------------------------------------------------------------------ *)
type skey
type pkey

val honest: alg -> pkey -> bool

val create_pkey: alg -> CoreSig.sigpkey -> pkey

val sigalg_of_skeyparams : CoreSig.sigskey -> sigAlg
val sigalg_of_pkeyparams : CoreSig.sigpkey -> sigAlg

(* ------------------------------------------------------------------------ *)
val gen    : alg -> pkey * skey
val sign   : alg -> skey -> text -> sigv
val verify : alg -> pkey -> text -> sigv -> bool
val coerce :  alg -> pkey -> CoreSig.sigskey -> skey
