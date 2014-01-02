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

module StatefulLHAE

open Bytes
open Error
open TLSInfo
open Range

open StatefulPlain

type rw =
    | ReaderState
    | WriterState
type state
type reader = state
type writer = state

val GEN: epoch -> reader * writer
val COERCE: epoch -> rw -> bytes -> state
val LEAK: epoch -> rw -> state -> bytes

val history: epoch -> rw -> state -> history

type cipher = ENC.cipher

val encrypt: epoch -> writer ->  adata -> range -> plain -> (writer * cipher)

val decrypt: epoch -> reader ->  adata -> cipher -> (reader * range * plain) Result
