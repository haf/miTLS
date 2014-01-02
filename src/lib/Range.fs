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
open TLSConstants
open TLSInfo

type range = nat * nat
type rbytes = bytes

let sum (l0,h0) (l1,h1) =
  let l = l0 + l1
  let h = h0 + h1
  (l,h)

let ivSize (e:id) =
    let authEnc = e.aeAlg
    match authEnc with
    | MACOnly _ -> 0
    | MtE (encAlg,_) ->
        match encAlg with
        | Stream_RC4_128 -> 0
        | CBC_Stale(_) -> 0
        | CBC_Fresh(alg) -> blockSize alg
    | AEAD (_,_) -> Error.unexpected "[ivSize] invoked on wrong ciphersuite"

let fixedPadSize (id:id) = 1

let maxPadSize id =
    let authEnc = id.aeAlg in
    match authEnc with
    | MACOnly _ | AEAD(_,_) -> 0
    | MtE(enc,_) ->

            match enc with
            | Stream_RC4_128 -> 0
            | CBC_Stale(alg) | CBC_Fresh(alg) ->
                match pv_of_id id with
                | SSL_3p0 -> blockSize alg
                | TLS_1p0 | TLS_1p1 | TLS_1p2 -> 255

let blockAlignPadding e len =
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly _ | AEAD(_,_) -> 0
    | MtE(enc,_) ->
        match enc with
        | Stream_RC4_128 -> 0
        | CBC_Stale(alg) | CBC_Fresh(alg) ->
            let bs = blockSize alg in
            let fp = fixedPadSize e in
            let x = len + fp in
            let overflow = x % bs //@ at least fp bytes of fixed padding
            let y = bs - overflow in
            if overflow = 0
            then fp
            else fp + y

//@ From plaintext range to ciphertext length
let targetLength e (rg:range) =
    let (_,h) = rg in
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly _ | MtE(_,_) ->
        let macLen = macSize (macAlg_of_id e) in
        let ivL = ivSize e in
        let prePad = h + macLen in
        let padLen = blockAlignPadding e prePad in
        let res = ivL + prePad + padLen in
        if res > max_TLSCipher_fragment_length then
            Error.unexpected "[targetLength] given an invalid input range."
        else
            res
    | AEAD(aeadAlg,_) ->
        let ivL = aeadRecordIVSize aeadAlg in
        let tagL = aeadTagSize aeadAlg in
        let res = ivL + h + tagL in
        if res > max_TLSCipher_fragment_length then
            Error.unexpected "[targetLength] given an invalid input range."
        else
            res

let minMaxPad (i:id) =
    let maxPad = maxPadSize i in
    if maxPad = 0 then
        (0,0)
    else
        let fp = fixedPadSize i in
        (fp,maxPad)

//@ From ciphertext length to (maximal) plaintext range
let cipherRangeClass (e:id) tlen =
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly _ | MtE(_,_) ->
        let macSize = macSize (macAlg_of_id e) in
        let ivL = ivSize e in
        let (minPad,maxPad) = minMaxPad e in
        let max = tlen - ivL - macSize - minPad in
        if max < 0 then
            Error.unexpected "[cipherRangeClass] the given tlen should be of a valid ciphertext"
        else
            let min = max - maxPad in
            if min < 0 then
                (0,max)
            else
                (min,max)
    | AEAD(aeadAlg,_) ->
        let ivL = aeadRecordIVSize aeadAlg in
        let tagL = aeadTagSize aeadAlg in
        let pLen = tlen - ivL - tagL in
        (pLen,pLen)

let rangeClass (e:id) (r:range) =
    let tlen = targetLength e r in
    cipherRangeClass e tlen
