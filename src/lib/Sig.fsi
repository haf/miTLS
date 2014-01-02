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

module Sig

open Bytes
open TLSConstants

(* ------------------------------------------------------------------------ *)
type alg  = sigAlg * hashAlg

type text = bytes
type sigv = bytes

(* ------------------------------------------------------------------------ *)
type skey
type pkey

val create_skey: hashAlg -> CoreSig.sigskey -> skey
val create_pkey: hashAlg -> CoreSig.sigpkey -> pkey

val repr_of_skey: skey -> CoreSig.sigskey * hashAlg
val repr_of_pkey: pkey -> CoreSig.sigpkey * hashAlg

val sigalg_of_skeyparams : CoreSig.sigskey -> sigAlg
val sigalg_of_pkeyparams : CoreSig.sigpkey -> sigAlg

(* ------------------------------------------------------------------------ *)
val gen    : alg -> pkey * skey
val sign   : alg -> skey -> text -> sigv
val verify : alg -> pkey -> text -> sigv -> bool
