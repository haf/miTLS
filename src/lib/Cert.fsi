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

module Cert

open Bytes
open Error
open TLSError
open UntrustedCert

type hint = UntrustedCert.hint
type cert = UntrustedCert.cert

type chain = UntrustedCert.chain
type sign_cert = option<(chain * Sig.alg * Sig.skey)>
type enc_cert  = option<(chain * RSAKey.sk)>

val for_signing : list<Sig.alg> -> hint -> list<Sig.alg> -> sign_cert
val for_key_encryption : list<Sig.alg> -> hint -> enc_cert

val get_public_signing_key : cert -> Sig.alg -> Result<Sig.pkey>
val get_public_encryption_key : cert -> Result<RSAKey.pk>

val get_chain_public_signing_key : chain -> Sig.alg -> Result<Sig.pkey>
val get_chain_public_encryption_key : chain -> Result<RSAKey.pk>

val is_chain_for_signing : chain -> bool
val is_chain_for_key_encryption : chain -> bool

val get_hint : chain -> option<hint>
val validate_cert_chain : list<Sig.alg> -> chain -> bool
val parseCertificateList: bytes -> Result<chain>
val certificateListBytes: chain -> bytes
