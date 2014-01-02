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

module CoreHMac

type engine
type key = byte array

val name   : engine -> string
val mac    : engine -> byte array -> byte array

val md5engine    : key -> engine
val sha1engine   : key -> engine
val sha256engine : key -> engine
val sha384engine : key -> engine
val sha512engine : key -> engine

val md5    : key -> byte array -> byte array
val sha1   : key -> byte array -> byte array
val sha256 : key -> byte array -> byte array
val sha384 : key -> byte array -> byte array
val sha512 : key -> byte array -> byte array
