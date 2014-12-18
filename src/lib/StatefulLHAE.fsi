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

module StatefulLHAE

open Bytes
open Error
open TLSError
open TLSInfo
open Range
open StatefulPlain

type state
type reader = state
type writer = state

val GEN:     id -> reader * writer
val COERCE:  id -> rw -> bytes -> state
val LEAK:    id -> rw -> state -> bytes

val history: id -> rw -> state -> history

type cipher = LHAE.cipher

val encrypt: id -> writer ->  adata -> range -> plain -> (writer * cipher)
val decrypt: id -> reader ->  adata -> cipher -> Result<(reader * range * plain)>
