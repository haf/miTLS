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

module TLSPRF

open Bytes
open TLSConstants

(* Verify data *)
val ssl_verifyData : bytes -> bytes  -> bytes -> bytes
val tls_verifyData : bytes -> string -> bytes -> bytes
val tls12VerifyData: cipherSuite -> bytes -> string -> bytes -> bytes

(* PRF *)
val prf: ProtocolVersion -> cipherSuite -> bytes -> string -> bytes -> int -> bytes

(* SSL-specific certificate verify *)
val ssl_certificate_verify: bytes -> bytes -> hashAlg -> bytes
