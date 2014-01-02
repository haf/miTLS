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

module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream

type fragment
val fragment: epoch -> stream -> range -> delta -> fragment * stream
val delta: epoch -> stream -> range -> fragment -> delta * stream

type plain = fragment

val plain: epoch -> range -> bytes -> fragment
val repr: epoch -> range -> fragment -> bytes

#if ideal
val widen: epoch -> range -> fragment -> fragment
#endif
