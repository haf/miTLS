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

module Record

open Bytes
open Tcp
open TLSConstants
open Error
open TLSError
open TLSInfo
open Range

/// Implements stateful AE on top of LHAE,
/// managing sequence numbers and the binary record format

type ConnectionState
type sendState = ConnectionState
type recvState = ConnectionState

val initConnState: epoch -> rw -> StatefulLHAE.state -> ConnectionState
val nullConnState: epoch -> rw -> ConnectionState

val parseHeader: bytes -> Result<(ContentType * ProtocolVersion * nat)>

val recordPacketOut: epoch -> sendState -> ProtocolVersion -> range -> ContentType -> TLSFragment.fragment -> (sendState * bytes)
val recordPacketIn : epoch -> recvState -> ContentType -> bytes -> Result<(recvState * range * TLSFragment.fragment)>

val history: epoch -> rw -> ConnectionState -> TLSFragment.history
