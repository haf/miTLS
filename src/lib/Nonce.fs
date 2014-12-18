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

module Nonce

open Bytes
open Error

let timestamp () = bytes_of_int 4 (Date.secondsFromDawn ())

let random (n:nat) =
  let r = CoreRandom.random n in
  let l = length r in
  if l = n then r
  else unexpected "CoreRandom.random returned incorrect number of bytes"

let noCsr = random 64 // a constant value, with negligible probability of being sampled, excluded by idealization

#if ideal
let log = ref []
#endif

let rec mkHelloRandom(): bytes =
    let Cr = timestamp() @| random 28 in
    //#begin-idealization
    #if ideal
    if List.memr !log Cr then
        mkHelloRandom () // we formally retry to exclude collisions.
    else
        (log := Cr::!log;
        Cr)
    #else //#end-idealization
    Cr
    #endif
