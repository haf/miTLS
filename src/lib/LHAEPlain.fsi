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

module LHAEPlain
open Bytes
open TLSInfo
open Range
open TLSError

type adata = bytes
type fragment
type plain = fragment

val plain: id -> adata -> range -> bytes -> plain
val repr:  id -> adata -> range -> plain -> bytes

val makeAD: id -> StatefulPlain.history -> StatefulPlain.adata -> adata
val parseAD: id -> adata -> StatefulPlain.adata
val StatefulPlainToLHAEPlain: id -> StatefulPlain.history -> StatefulPlain.adata -> adata -> range -> StatefulPlain.plain -> plain
val LHAEPlainToStatefulPlain: id -> StatefulPlain.history -> StatefulPlain.adata -> adata -> range -> plain -> StatefulPlain.plain

val makeExtPad:  id -> adata -> range -> plain -> plain
val parseExtPad: id -> adata -> range -> plain -> Result<plain>

#if ideal
val widen: id -> adata -> range -> fragment -> fragment
#endif
