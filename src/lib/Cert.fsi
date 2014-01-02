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

module Cert

open Bytes
open Error

type hint = string (* hostname CN *)
type cert = bytes  (* public part of a certificate *)

type chain = cert list
type sign_cert = (chain * Sig.alg * Sig.skey) option
type enc_cert  = (chain * RSAKey.sk) option

(* First argument (Sig.alg list) for both functions gives the allowed
 * signing alg. used for signing the key. For [for_signing] TLS1.2
 * allows the signing alg. used for the key to be different from the
 * signing alg. that can be used with that key.
 *)
val for_signing : Sig.alg list -> hint -> Sig.alg list -> sign_cert
val for_key_encryption : Sig.alg list -> hint -> enc_cert

val get_public_signing_key : cert -> Sig.alg -> Sig.pkey Result
val get_public_encryption_key : cert -> RSAKey.pk Result

val is_for_signing : cert -> bool
val is_for_key_encryption : cert -> bool

val get_chain_public_signing_key : chain -> Sig.alg -> Sig.pkey Result
val get_chain_public_encryption_key : chain -> RSAKey.pk Result

val is_chain_for_signing : chain -> bool
val is_chain_for_key_encryption : chain -> bool

val get_chain_key_algorithm : chain -> TLSConstants.sigAlg option

val get_hint : chain -> hint option

(* First argument (Sig.alg list) gives the allowed signing alg. used for
 * signing the keys of the chain.
 *)
val validate_cert_chain : Sig.alg list -> chain -> bool

val certificateListBytes: chain -> bytes
val parseCertificateList: bytes -> chain -> chain Result
