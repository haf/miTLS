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

module Date

type DateTime
type TimeSpan
val now: unit -> DateTime
val secondsFromDawn: unit -> int
val newTimeSpan: int -> int -> int -> int -> TimeSpan
val addTimeSpan: DateTime -> TimeSpan -> DateTime
val greaterDateTime: DateTime -> DateTime -> bool
