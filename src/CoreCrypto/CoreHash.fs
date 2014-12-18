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

module CoreHash
open Bytes

open CryptoProvider

(* ---------------------------------------------------------------------- *)
type engine = HashEngine of MessageDigest

let name (HashEngine engine) =
    engine.Name

let digest (HashEngine engine) (b : bytes) =
    abytes (engine.Digest (cbytes b))

(* ---------------------------------------------------------------------- *)
let md5engine    () = HashEngine (CoreCrypto.Digest "MD5"   )
let sha1engine   () = HashEngine (CoreCrypto.Digest "SHA1"  )
let sha256engine () = HashEngine (CoreCrypto.Digest "SHA256")
let sha384engine () = HashEngine (CoreCrypto.Digest "SHA384")
let sha512engine () = HashEngine (CoreCrypto.Digest "SHA512")

(* ---------------------------------------------------------------------- *)
let dohash (factory : unit -> engine) (x : bytes) =
    let engine = factory () in
        (digest engine x)

let md5    x = dohash md5engine    x
let sha1   x = dohash sha1engine   x
let sha256 x = dohash sha256engine x
let sha384 x = dohash sha384engine x
let sha512 x = dohash sha512engine x
