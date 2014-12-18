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

module PMS

open Bytes
open TLSConstants
open Error
open TLSError
open DHGroup
open CoreKeys

type rsarepr = bytes
type rsaseed = {seed: rsarepr}
type rsapms =
#if ideal
  | IdealRSAPMS of rsaseed
#endif
  | ConcreteRSAPMS of rsarepr

type dhrepr = bytes
type dhseed = {seed: dhrepr}

type dhpms =
#if ideal
  | IdealDHPMS of dhseed
#endif
  | ConcreteDHPMS of dhrepr

#if ideal
val honestRSAPMS: RSAKey.pk -> TLSConstants.ProtocolVersion -> rsapms -> bool
#endif

val genRSA: RSAKey.pk -> TLSConstants.ProtocolVersion -> rsapms

val coerceRSA: RSAKey.pk -> ProtocolVersion -> rsarepr -> rsapms
val leakRSA: RSAKey.pk -> ProtocolVersion -> rsapms -> rsarepr

#if ideal
val honestDHPMS: bytes -> bytes -> elt -> elt -> dhpms -> bool
#endif

val sampleDH: dhparams -> DHGroup.elt -> DHGroup.elt -> dhpms

val coerceDH: dhparams -> DHGroup.elt -> DHGroup.elt -> DHGroup.elt -> dhpms

(* Used when generating key material from the MS.
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)

type pms =
  | RSAPMS of RSAKey.pk * ProtocolVersion * rsapms
  | DHPMS of bytes * bytes * elt * elt * dhpms
