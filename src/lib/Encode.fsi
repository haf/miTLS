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

module Encode

open Bytes
open Error
open TLSError
open TLSInfo
open TLSConstants
open Range

type plain
val plain: id -> LHAEPlain.adata -> nat -> bytes -> plain
val repr:  id -> LHAEPlain.adata -> range -> plain -> bytes

val mac: id -> MAC.key -> LHAEPlain.adata -> range -> LHAEPlain.plain -> plain
val verify: id -> MAC.key -> LHAEPlain.adata -> range -> plain -> Result<LHAEPlain.plain>

val decodeNoPad_bytes: id -> LHAEPlain.adata -> range -> nat -> lbytes -> rbytes * MAC.tag
val verify_MACOnly: id -> MAC.key -> LHAEPlain.adata -> range -> nat -> rbytes -> MAC.tag ->
    Result<range*LHAEPlain.plain>

#if ideal
val widen: id -> LHAEPlain.adata -> range -> plain -> plain
#endif
