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

module LHAE

open Bytes
open Error
open TLSError
open TLSInfo
open LHAEPlain
open Range

type LHAEKey
type encryptor = LHAEKey
type decryptor = LHAEKey

type cipher = bytes

val GEN: id -> encryptor * decryptor
val COERCE: id -> rw -> bytes -> LHAEKey
val LEAK: id -> rw -> LHAEKey -> bytes

val encrypt: id -> encryptor -> adata ->
             range -> plain -> (encryptor * cipher)
val decrypt: id -> decryptor -> adata ->
             cipher -> Result<(decryptor * range * plain)>
