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
open TLSInfo

val verifyData: prfAlg -> bytes -> Role -> bytes -> bytes
val extract: creAlg -> bytes -> bytes -> int -> bytes
val kdf: prfAlg -> bytes -> bytes -> int -> bytes

(* SSL-specific certificate verify *)

val ssl_verifyCertificate: hashAlg -> bytes -> bytes -> bytes
