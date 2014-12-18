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

module CoreHMac
open Bytes
open CryptoProvider

type engine = HMac of CryptoProvider.HMac
type key    = bytes

let name (HMac engine) =
    engine.Name

let mac (HMac engine) (b : bytes) =
    abytes (engine.Process(cbytes b))

let md5engine    (k : key) = HMac (CoreCrypto.HMac "MD5"    (cbytes k))
let sha1engine   (k : key) = HMac (CoreCrypto.HMac "SHA1"   (cbytes k))
let sha256engine (k : key) = HMac (CoreCrypto.HMac "SHA256" (cbytes k))
let sha384engine (k : key) = HMac (CoreCrypto.HMac "SHA384" (cbytes k))
let sha512engine (k : key) = HMac (CoreCrypto.HMac "SHA512" (cbytes k))

let dohmac (factory : key -> engine) (k : key) (data : bytes) =
    mac (factory k) data

let md5    (k : key) (data : bytes) = dohmac md5engine    k data
let sha1   (k : key) (data : bytes) = dohmac sha1engine   k data
let sha256 (k : key) (data : bytes) = dohmac sha256engine k data
let sha384 (k : key) (data : bytes) = dohmac sha384engine k data
let sha512 (k : key) (data : bytes) = dohmac sha512engine k data
