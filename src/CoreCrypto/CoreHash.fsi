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

type engine

val name   : engine -> string
val update : engine -> byte array -> unit
val hash   : engine -> byte array
val reset  : engine -> unit

val md5engine    : unit -> engine
val sha1engine   : unit -> engine
val sha256engine : unit -> engine
val sha384engine : unit -> engine
val sha512engine : unit -> engine

val md5    : byte array -> byte array
val sha1   : byte array -> byte array
val sha256 : byte array -> byte array
val sha384 : byte array -> byte array
val sha512 : byte array -> byte array
