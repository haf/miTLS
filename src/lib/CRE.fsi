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

module CRE

open Bytes
open TLSConstants
open TLSInfo
open Error

type rsarepr = bytes
type rsapms
type dhpms

#if ideal

type pms = RSA_pms of rsapms | DHE_pms of dhpms
val corrupt: pms -> bool
#endif

val genRSA: RSAKey.pk -> TLSConstants.ProtocolVersion -> rsapms

val coerceRSA: RSAKey.pk -> ProtocolVersion -> rsarepr -> rsapms
val leakRSA: RSAKey.pk -> ProtocolVersion -> rsapms -> rsarepr

val sampleDH: DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> dhpms

val coerceDH: DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> DHGroup.elt -> dhpms

val prfSmoothRSA: SessionInfo -> ProtocolVersion -> rsapms -> PRF.masterSecret
val prfSmoothDHE: SessionInfo -> DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> dhpms -> PRF.masterSecret

(* Used when generating key material from the MS.
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)
