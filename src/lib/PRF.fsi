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
open TLSInfo

type repr = bytes
type masterSecret

#if ideal
val sample: SessionInfo -> masterSecret
#endif

val keyGen: ConnectionInfo -> masterSecret -> StatefulLHAE.writer * StatefulLHAE.reader

val makeVerifyData:  epoch -> Role -> masterSecret -> bytes -> bytes
val checkVerifyData: epoch -> Role -> masterSecret -> bytes -> bytes -> bool

val ssl_certificate_verify: SessionInfo -> masterSecret -> TLSConstants.sigAlg -> bytes -> bytes

//#begin-coerce
val coerce: SessionInfo -> repr -> masterSecret
//#end-coerce
