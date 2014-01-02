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

module CoreHash

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Digests

type engine = HashEngine of IDigest

let name (HashEngine engine) =
    engine.AlgorithmName

let update (HashEngine engine) (data : byte[]) =
    engine.BlockUpdate(data, 0, data.Length)

let hash (HashEngine engine) =
    let output = Array.create (engine.GetDigestSize()) 0uy in
        ignore (engine.DoFinal(output, 0));
        output

let reset (HashEngine engine) =
    engine.Reset()

let md5engine    () = HashEngine (new MD5Digest    () :> IDigest)
let sha1engine   () = HashEngine (new Sha1Digest   () :> IDigest)
let sha256engine () = HashEngine (new Sha256Digest () :> IDigest)
let sha384engine () = HashEngine (new Sha384Digest () :> IDigest)
let sha512engine () = HashEngine (new Sha512Digest () :> IDigest)

let dohash (factory : unit -> engine) (x : byte[]) =
    let engine = factory () in
        update engine x; hash engine

let md5    x = dohash md5engine    x
let sha1   x = dohash sha1engine   x
let sha256 x = dohash sha256engine x
let sha384 x = dohash sha384engine x
let sha512 x = dohash sha512engine x
