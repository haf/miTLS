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

module HMAC

open Bytes
open TLSConstants

type key = bytes
type data = bytes
type mac = bytes

(* SSL3 keyed hash *)

let sslKeyedHashPads alg =
  match alg with
    | MD5 -> (ssl_pad1_md5, ssl_pad2_md5)
    | SHA -> (ssl_pad1_sha1, ssl_pad2_sha1)
    | _   -> Error.unexpectedError "[sslKeyedHashPads] invoked on unsupported algorithm"

let sslKeyedHash alg key data =
    let (pad1, pad2) = sslKeyedHashPads alg in
    let dataStep1 = key @| pad1 @| data in
    let step1 = HASH.hash alg dataStep1 in
    let dataStep2 = key @| pad2 @| step1 in
    HASH.hash alg dataStep2

let sslKeyedHashVerify alg key data expected =
    let result = sslKeyedHash alg key data in
    equalBytes result expected

(* Parametric keyed hash *)

let HMAC alg key data =
    match alg with
    | MD5     -> CoreHMac.md5    key data
    | SHA     -> CoreHMac.sha1   key data
    | SHA256  -> CoreHMac.sha256 key data
    | SHA384  -> CoreHMac.sha384 key data
    | NULL    -> Error.unexpectedError "[HMAC] Invalid hash (NULL) for HMAC"
    | MD5SHA1 -> Error.unexpectedError "[HMAC] Invalid hash (MD5SHA1) for HMAC"

let HMACVERIFY alg key data expected =
    let result = HMAC alg key data in
    equalBytes result expected

(* Top level MAC function *)

let MAC a k d =
    match a with
    | MA_HMAC(alg) -> HMAC alg k d
    | MA_SSLKHASH(alg) -> sslKeyedHash alg k d

let MACVERIFY a k d t =
    match a with
    | MA_HMAC(alg) -> HMACVERIFY alg k d t
    | MA_SSLKHASH(alg) -> sslKeyedHashVerify alg k d t
