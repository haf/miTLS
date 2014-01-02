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

module StatefulPlain
open Bytes
open TLSConstants
open TLSInfo
open Range

type adata = bytes

type fragment
type prehistory = (adata * range * fragment) list
type history  = (nat * prehistory)
type plain = fragment

//------------------------------------------------------------------------------
val plain: epoch -> history -> adata -> range -> bytes -> plain
val reprFragment:  epoch -> adata -> range -> fragment -> bytes
val repr:  epoch -> history -> adata -> range -> plain -> bytes

//------------------------------------------------------------------------------
val emptyHistory: epoch -> history
val extendHistory: epoch -> adata -> history -> range -> fragment -> history

val makeAD: epoch -> ContentType -> adata
val parseAD: epoch -> adata -> ContentType
val RecordPlainToStAEPlain: epoch -> ContentType -> TLSFragment.history -> history -> range -> TLSFragment.plain -> plain
val StAEPlainToRecordPlain: epoch -> ContentType -> TLSFragment.history -> history -> range -> plain -> TLSFragment.plain

#if ideal
val widen: epoch -> adata -> range -> fragment -> fragment
#endif
