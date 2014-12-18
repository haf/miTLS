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

module ENC

open Bytes
open TLSInfo

type state
type encryptor = state
type decryptor = state

val GEN:    id -> encryptor * decryptor
val LEAK:   id -> rw -> state -> bytes * bytes
val COERCE: id -> rw -> bytes -> bytes-> state

type cipher = bytes

val ENC: id -> encryptor -> LHAEPlain.adata -> Range.range -> Encode.plain -> (encryptor * cipher)
val DEC: id -> decryptor -> LHAEPlain.adata -> cipher -> (decryptor * Encode.plain)
