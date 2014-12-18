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

module Tcp

open Bytes
open Error

type NetworkStream
type TcpListener

(* Create a network stream from a given stream.
   Only used by the application interface TLSharp. *)

val create: System.IO.Stream -> NetworkStream

(* Server side *)

val listen: string -> int -> TcpListener
val acceptTimeout: int -> TcpListener -> NetworkStream
val accept: TcpListener -> NetworkStream
val stop: TcpListener -> unit

(* Client side *)

val connectTimeout: int -> string -> int -> NetworkStream
val connect: string -> int -> NetworkStream

(* Input/Output *)

val read: NetworkStream -> int -> (string,bytes) optResult
val write: NetworkStream -> bytes -> (string,unit) optResult
val close: NetworkStream -> unit
