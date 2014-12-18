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

module AppData

open TLSInfo
open Bytes
open Error
open TLSError
open DataStream
open Range

type app_state

val inStream:  ConnectionInfo -> app_state -> stream
val outStream: ConnectionInfo -> app_state -> stream

val init:           ConnectionInfo -> app_state
val writeAppData:   ConnectionInfo -> app_state -> range -> AppFragment.fragment -> stream -> app_state
val next_fragment:  ConnectionInfo -> app_state -> option<(range * AppFragment.fragment * app_state)>
val clearOutBuf:    ConnectionInfo -> app_state -> app_state

val recv_fragment:  ConnectionInfo -> app_state -> range -> AppFragment.fragment -> delta * app_state

val reset_incoming: ConnectionInfo -> app_state -> ConnectionInfo -> app_state
val reset_outgoing: ConnectionInfo -> app_state -> ConnectionInfo -> app_state
