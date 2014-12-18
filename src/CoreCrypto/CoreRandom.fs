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

module CoreRandom

open Org.BouncyCastle.Security

let provider = new SecureRandom()

let random (i : int) =
    if i < 0 then
        invalidArg "length" "must be non-negative";

    let bytes = Array.create i 0uy in
        lock provider (fun () -> provider.NextBytes(bytes, 0, i));
        Bytes.abytes bytes
