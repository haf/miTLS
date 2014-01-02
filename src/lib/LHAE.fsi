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

module LHAE

open Bytes
open Error
open TLSInfo
open LHAEPlain
open Range

type LHAEKey

type cipher = bytes

val GEN: epoch -> LHAEKey * LHAEKey
val COERCE: epoch -> bytes -> LHAEKey
val LEAK: epoch -> LHAEKey -> bytes

val encrypt: epoch -> LHAEKey -> adata ->
             range -> plain -> (LHAEKey * cipher)
val decrypt: epoch -> LHAEKey -> adata ->
             cipher -> (LHAEKey * range * plain) Result
