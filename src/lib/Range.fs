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

module Range

open Bytes
open TLSInfo
open TLSConstants

type range = nat * nat
type rbytes = bytes

let rangeSum (l0,h0) (l1,h1) =
  let l = l0 + l1
  let h = h0 + h1
  (l,h)

let ivSize e =
    let si = epochSI(e) in
    let authEnc = authencAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match authEnc with
    | MACOnly _ -> 0
    | MtE (encAlg,_) ->
        match encAlg with
        | Stream_RC4_128 -> 0
        | CBC_Stale(_) -> 0
        | CBC_Fresh(alg) -> blockSize alg
    | AEAD (_,_) -> Error.unexpectedError "[ivSize] invoked on unsupported ciphersuite"

let fixedPadSize (si:SessionInfo) = 1

let maxPadSize si =
    let authEnc = authencAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match authEnc with
    | MACOnly _ -> 0
    | MtE(enc,_) ->

            match enc with
            | Stream_RC4_128 -> 0
            | CBC_Stale(alg) | CBC_Fresh(alg) ->
                match si.protocol_version with
                | SSL_3p0 -> blockSize alg
                | TLS_1p0 | TLS_1p1 | TLS_1p2 -> 255
    | _ -> Error.unexpectedError "[maxPadSize] invoked on unsupported ciphersuite"

let blockAlignPadding e len =
    let si = epochSI(e) in
    let authEnc = authencAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match authEnc with
    | MACOnly _ -> 0
    | MtE(enc,_) ->
        match enc with
        | Stream_RC4_128 -> 0
        | CBC_Stale(alg) | CBC_Fresh(alg) ->
            let bs = blockSize alg in
            let fp = fixedPadSize si in
            let overflow = (len + fp) % bs //@ at least fp bytes of fixed padding
            if overflow = 0 then fp else fp + bs - overflow
    | _ -> Error.unexpectedError "[maxPadSize] invoked on unsupported ciphersuite"

//@ From plaintext range to ciphertext length
let targetLength e (rg:range) =
    let (_,h) = rg in
    let si = epochSI(e) in
    let macLen = macSize (macAlg_of_ciphersuite si.cipher_suite si.protocol_version) in
    let ivL = ivSize e in
    let prePad = h + macLen in
    let padLen = blockAlignPadding e prePad in
    let res = ivL + prePad + padLen in
    if res > max_TLSCipher_fragment_length then
        Error.unexpectedError "[targetLength] given an invalid input range."
    else
        res

let minMaxPad si =
    let maxPad = maxPadSize si in
    if maxPad = 0 then
        (0,0)
    else
        let fp = fixedPadSize si in
        (fp,maxPad)

//@ From ciphertext length to (maximal) plaintext range
let cipherRangeClass (e:epoch) tlen =
    let si = epochSI(e) in
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite si.protocol_version) in
    let ivL = ivSize e in
    let (minPad,maxPad) = minMaxPad si in
    let max = tlen - ivL - macSize - minPad in
    if max < 0 then
        Error.unexpectedError "[cipherRangeClass] the given tlen should be of a valid ciphertext"
    else
        let min = max - maxPad in
        if min < 0 then
            let rg = (0,max) in
            rg
        else
            let rg = (min,max) in
            rg

let rangeClass (e:epoch) (r:range) =
    let tlen = targetLength e r in
    cipherRangeClass e tlen
