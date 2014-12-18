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

module PRF

open Bytes
open TLSConstants
open TLSInfo

type repr = bytes
type ms
type masterSecret = ms

#if ideal
val sample: msId -> ms
#endif

//#begin-coerce
val coerce: msId -> repr -> ms
//#end-coerce
val leak: msId -> ms -> repr

val deriveKeys: id -> id -> ms -> Role -> StatefulLHAE.state * StatefulLHAE.state

val keyCommit: csrands -> ProtocolVersion -> aeAlg -> negotiatedExtensions -> unit
val keyGenClient: id -> id -> ms -> StatefulLHAE.writer * StatefulLHAE.reader
val keyGenServer: id -> id -> ms -> StatefulLHAE.writer * StatefulLHAE.reader

val makeVerifyData:  SessionInfo -> ms -> Role -> bytes -> bytes
val checkVerifyData: SessionInfo -> ms -> Role -> bytes -> bytes -> bool

val ssl_certificate_verify: SessionInfo -> ms -> TLSConstants.sigAlg -> bytes -> bytes
