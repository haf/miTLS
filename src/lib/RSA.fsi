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

module RSA

open TLSInfo
open Bytes
open TLSConstants

val encrypt: RSAKey.pk -> ProtocolVersion -> CRE.rsapms -> bytes

// This is not just plain RSA_PKCS1 decryption.
// We put in place timing attack countermeasures.
// See RFC 5246, section 7.4.7.1
val decrypt: RSAKey.sk -> SessionInfo -> ProtocolVersion -> bool -> bytes -> CRE.rsapms
