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

module LHAEPlain
open Bytes
open TLSInfo
open Range

type adata = bytes
type fragment
type plain = fragment

val plain: epoch -> adata -> range -> bytes -> plain
val repr:  epoch -> adata -> range -> plain -> bytes

val makeAD: epoch -> StatefulPlain.history -> StatefulPlain.adata -> adata
val parseAD: epoch -> adata -> StatefulPlain.adata
val StatefulPlainToLHAEPlain: epoch -> StatefulPlain.history -> StatefulPlain.adata -> range -> StatefulPlain.plain -> plain
val LHAEPlainToStatefulPlain: epoch -> StatefulPlain.history -> StatefulPlain.adata -> range -> plain -> StatefulPlain.plain

#if ideal
val widen: epoch -> adata -> range -> fragment -> fragment
#endif
