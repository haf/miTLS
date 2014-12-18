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

module UTLS

open Error
open TLSError
open Bytes
open TLSInfo
open Dispatch

type rawfd   = Tcp.NetworkStream
type fd      = int
type queryhd = int

val EI_BADHANDLE  : int
val EI_BADCERTIDX : int
val EI_READERROR  : int
val EI_CLOSE      : int
val EI_FATAL      : int
val EI_WARNING    : int
val EI_CERTQUERY  : int
val EI_HANDSHAKEN : int
val EI_DONTWRITE  : int
val EI_WRITEERROR : int
val EI_MUSTREAD   : int
val EI_HSONGOING  : int

val canwrite : fd -> int
val read     : fd -> int * bytes
val write    : fd -> bytes -> int
val shutdown : fd -> unit

val connect          : rawfd -> config -> fd
val accept_connected : rawfd -> config -> fd
