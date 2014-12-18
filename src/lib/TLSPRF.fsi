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

module TLSPRF

open Bytes
open TLSConstants
open TLSInfo

val verifyData: vdAlg -> bytes -> Role -> bytes -> bytes
val extract: kefAlg -> bytes -> bytes -> int -> bytes
val kdf: kdfAlg -> bytes -> bytes -> int -> bytes

(* SSL-specific certificate verify *)

val ssl_verifyCertificate: hashAlg -> bytes -> bytes -> bytes
