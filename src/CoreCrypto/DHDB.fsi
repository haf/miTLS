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

module DHDB

open Bytes

// p, g, q, true  => prime(p) /\ prime(q) /\ g^q mod p = 1 /\ p = 2*q + 1
// p, g, q, false => prime(p) /\ prime(q) /\ g^q mod p = 1 /\ ?j. p = j*q + 1 /\ length(q) >= threshold
type Key   = bytes * bytes // p, g
type Value = bytes * bool  // q, safe_prime?

type dhdb

val create: string -> dhdb
val select: dhdb -> Key -> Value option
val insert: dhdb -> Key -> Value -> dhdb
val remove: dhdb -> Key -> dhdb
val keys  : dhdb -> Key list
