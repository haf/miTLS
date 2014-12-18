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

module AEAD_GCM

open Bytes
open TLSInfo
open Range
open TLSError

type cipher = bytes
type state
type encryptor = state
type decryptor = state

val GEN: id -> encryptor * decryptor
val COERCE: id -> rw -> bytes -> bytes -> state
val LEAK: id -> rw -> state -> bytes

val ENC: id -> encryptor -> LHAEPlain.adata -> range ->
  LHAEPlain.plain -> (encryptor * bytes)

val DEC: id -> decryptor -> LHAEPlain.adata -> range ->
  bytes -> Result<(decryptor * LHAEPlain.plain)>
