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

module Nonce

open Bytes

#if ideal
let log = ref []
#endif

open System

let dawn = new System.DateTime(1970, 1, 1)
let timestamp () = bytes_of_int 4 ((int32) (DateTime.UtcNow - dawn).TotalSeconds)

let rec mkHelloRandom(): bytes =
    let Cr = timestamp() @| random 28
    //#begin-idealization
    #if ideal
    if memr !log Cr then
        mkHelloRandom () // we formally retry to exclude collisions.
    else
        log := Cr::!log
        Cr
    #else //#end-idealization
    Cr
    #endif
