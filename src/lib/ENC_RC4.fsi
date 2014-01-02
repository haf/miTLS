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

module ENC_RC4

open Bytes
open Encode
open TLSInfo
open Error
open TLSError
open Range

type cipher = bytes
type keyrepr = bytes
type state
type encryptor = state
type decryptor = state

val GEN: id -> encryptor * decryptor
val ENC: id -> encryptor -> LHAEPlain.adata -> r:range -> plain -> encryptor * cipher
val DEC: id -> decryptor -> LHAEPlain.adata -> c:cipher -> decryptor * plain

val LEAK: id -> state -> bytes
val COERCEe: id -> keyrepr -> encryptor
val COERCEd: id -> keyrepr -> decryptor
