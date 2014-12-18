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

type DateTime = DT of System.DateTime
type TimeSpan = TS of System.TimeSpan
let now () = DT (System.DateTime.Now)
let dawn = new System.DateTime(1970, 1, 1)
let secondsFromDawn () = (int32) (System.DateTime.UtcNow - dawn).TotalSeconds
let newTimeSpan d h m s = TS (new System.TimeSpan(d,h,m,s))
let addTimeSpan (DT(a)) (TS(b)) = DT (a + b)
let greaterDateTime (DT(a)) (DT(b)) = a > b
