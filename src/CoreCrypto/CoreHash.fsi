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

module CoreHash
open Bytes

type engine

val name   : engine -> string
val digest : engine -> bytes -> bytes

val md5engine    : unit -> engine
val sha1engine   : unit -> engine
val sha256engine : unit -> engine
val sha384engine : unit -> engine
val sha512engine : unit -> engine

val md5    : bytes -> bytes
val sha1   : bytes -> bytes
val sha256 : bytes -> bytes
val sha384 : bytes -> bytes
val sha512 : bytes -> bytes
