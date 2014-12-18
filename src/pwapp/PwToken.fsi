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

module PwToken

// ------------------------------------------------------------------------
open Bytes
open TLSInfo
open DataStream
open Range

// ------------------------------------------------------------------------
type token
type username = string

val create   : unit -> token
val register : username -> token -> unit
val verify   : username -> token -> bool
val guess    : bytes -> token

// ------------------------------------------------------------------------
type delta = DataStream.delta

val MaxTkReprLen : int

val tk_repr  : epoch -> stream -> username -> token -> delta
val tk_plain : epoch -> stream -> range -> delta -> (username * token) option

val rp_repr  : epoch -> stream -> bool -> delta
val rp_plain : epoch -> stream -> range -> delta -> bool
