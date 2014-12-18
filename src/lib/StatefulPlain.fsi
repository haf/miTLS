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

module StatefulPlain

open Bytes
open TLSConstants
open TLSInfo
open Range
open Error
open TLSError

type adata = bytes

type fragment
type prehistory = list<(adata * range * fragment)>
type history  = (nat * prehistory)
type plain = fragment

//------------------------------------------------------------------------------
val plain: id -> history -> adata -> range -> bytes -> plain
val reprFragment:  id -> adata -> range -> fragment -> bytes
val repr:  id -> history -> adata -> range -> plain -> bytes

//------------------------------------------------------------------------------
val emptyHistory: id -> history
val extendHistory: id -> adata -> history -> range -> fragment -> history

val makeAD: id -> ContentType -> adata
val RecordPlainToStAEPlain: epoch -> ContentType -> adata -> TLSFragment.history -> history -> range -> TLSFragment.plain -> plain
val StAEPlainToRecordPlain: epoch -> ContentType -> adata -> TLSFragment.history -> history -> range -> plain -> TLSFragment.plain

val makeExtPad:  id -> adata -> range -> fragment -> fragment
val parseExtPad: id -> adata -> range -> fragment -> Result<fragment>

#if ideal
val widen: id -> adata -> range -> fragment -> fragment
#endif
