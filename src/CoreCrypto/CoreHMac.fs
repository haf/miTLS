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

module CoreHMac

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Macs
open Org.BouncyCastle.Crypto.Parameters

type engine = HMac of HMac
type key    = byte[]

let name (HMac engine) =
    engine.AlgorithmName

let update (HMac engine) (data : byte[]) =
    engine.BlockUpdate(data, 0, data.Length)

let mac (HMac engine) =
    let output = Array.create (engine.GetMacSize()) 0uy in
        ignore (engine.DoFinal(output, 0));
        output

let reset (HMac engine) =
    engine.Reset()

let new_engine (digest : IDigest) (k : key) =
    let engine = new HMac(digest) in
        engine.Init(new KeyParameter(k));
        HMac engine

let md5engine    (k : key) = new_engine (new MD5Digest   ()) k
let sha1engine   (k : key) = new_engine (new Sha1Digest  ()) k
let sha256engine (k : key) = new_engine (new Sha256Digest()) k
let sha384engine (k : key) = new_engine (new Sha384Digest()) k
let sha512engine (k : key) = new_engine (new Sha512Digest()) k

let dohmac (factory : key -> engine) (k : key) (data : byte[]) =
    let engine = factory k in
        update engine data; mac engine

let md5    (k : key) (data : byte[]) = dohmac md5engine    k data
let sha1   (k : key) (data : byte[]) = dohmac sha1engine   k data
let sha256 (k : key) (data : byte[]) = dohmac sha256engine k data
let sha384 (k : key) (data : byte[]) = dohmac sha384engine k data
let sha512 (k : key) (data : byte[]) = dohmac sha512engine k data
