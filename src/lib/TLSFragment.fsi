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

module TLSFragment

open Bytes
open TLSInfo
open TLSConstants
open Range
open TLSError

type history

type fragment
type plain = fragment

val emptyHistory: epoch -> history
val extendHistory: epoch -> ContentType -> history -> range -> fragment -> history

val handshakeHistory: epoch -> history -> HSFragment.stream
val ccsHistory: epoch -> history -> HSFragment.stream
val alertHistory: epoch -> history -> HSFragment.stream

val plain: epoch -> ContentType -> history -> range -> bytes -> plain Result
val fragment: id -> ContentType -> range -> bytes -> fragment Result
val reprFragment: id -> ContentType -> range -> fragment -> bytes
val repr:  epoch -> ContentType -> history -> range -> plain -> bytes

val HSPlainToRecordPlain     : epoch -> history -> range -> HSFragment.plain -> plain
val CCSPlainToRecordPlain    : epoch -> history -> range -> HSFragment.plain -> plain
val AlertPlainToRecordPlain  : epoch -> history -> range -> HSFragment.plain -> plain
val AppPlainToRecordPlain    : epoch -> history -> range -> AppFragment.plain -> plain
val RecordPlainToHSPlain     : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToCCSPlain    : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToAlertPlain  : epoch -> history -> range -> plain -> HSFragment.plain
val RecordPlainToAppPlain    : epoch -> history -> range -> plain -> AppFragment.plain

#if ideal
val widen: id -> ContentType -> range -> fragment -> fragment
#endif
