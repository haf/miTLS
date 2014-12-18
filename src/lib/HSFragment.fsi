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

module HSFragment
open Bytes
open TLSInfo
open Range
open Error
open TLSError

type stream

type fragment
type plain = fragment

val fragmentRepr: id -> range -> fragment -> bytes
val fragmentPlain: id -> range -> bytes -> fragment

val extend: id -> stream -> range -> fragment -> stream
val init: id -> stream

val reStream: id -> stream -> range -> plain -> stream -> plain

val makeExtPad:  id -> range -> fragment -> fragment
val parseExtPad: id -> range -> fragment -> Result<fragment>

#if ideal
val widen: id -> range -> range -> fragment -> fragment
#endif
