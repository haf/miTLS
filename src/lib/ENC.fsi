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

module ENC

open Bytes
open TLSInfo
open Error
open Range

type state
type encryptor = state
type decryptor = state

val GEN: epoch -> encryptor * decryptor
val LEAK: epoch -> state -> bytes * bytes
val COERCE: epoch -> bytes -> bytes-> state

type cipher = bytes

val ENC: epoch -> encryptor -> LHAEPlain.adata -> range -> Encode.plain -> (encryptor * cipher)
val DEC: epoch -> decryptor -> LHAEPlain.adata -> cipher -> (decryptor * Encode.plain)
