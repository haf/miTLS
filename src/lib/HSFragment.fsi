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

module HSFragment
open Bytes
open TLSInfo
open Range
open TLSError

type stream

type fragment
type plain = fragment

val userPlain: id -> range -> bytes -> fragment
val userRepr:  id -> range -> fragment -> bytes

val fragmentRepr: id -> range -> fragment -> bytes
val fragmentPlain: id -> range -> bytes -> fragment Result

val extend: id -> stream -> range -> fragment -> stream
val init: id -> stream

val reStream: id -> stream -> range -> plain -> stream -> plain

#if ideal
val widen: id -> range -> range -> fragment -> fragment
#endif
