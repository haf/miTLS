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

module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream
open TLSError

type preFragment
type fragment = preFragment
val fragment: epoch -> stream -> range -> delta -> fragment * stream
val delta: epoch -> stream -> range -> fragment -> delta * stream
type plain = fragment

val plain: id -> range -> bytes -> fragment
val repr:  id -> range -> fragment -> bytes

val makeExtPad:  id -> range -> fragment -> fragment
val parseExtPad: id -> range -> fragment -> Result<fragment>

#if ideal
val widen: id -> range -> fragment -> fragment
#endif
