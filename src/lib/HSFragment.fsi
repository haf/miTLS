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

type stream

type fragment
type plain = fragment

val fragmentRepr: epoch -> range -> fragment -> bytes
val fragmentPlain: epoch -> range -> bytes -> fragment

val extend: epoch -> stream -> range -> fragment -> stream
val init: epoch -> stream

val reStream: epoch -> stream -> range -> plain -> stream -> plain

#if ideal
val widen: epoch -> range -> range -> fragment -> fragment
#endif
