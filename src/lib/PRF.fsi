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
val coerce: msId -> repr -> masterSecret
//#end-coerce

val keyCommit: csrands -> ProtocolVersion -> aeAlg -> unit
val keyGenClient: id -> id -> masterSecret -> StatefulLHAE.writer * StatefulLHAE.reader
val keyGenServer: id -> id -> masterSecret -> StatefulLHAE.writer * StatefulLHAE.reader

val makeVerifyData:  SessionInfo -> masterSecret -> Role -> bytes -> bytes
val checkVerifyData: SessionInfo -> masterSecret -> Role -> bytes -> bytes -> bool

val ssl_certificate_verify: SessionInfo -> masterSecret -> TLSConstants.sigAlg -> bytes -> bytes
