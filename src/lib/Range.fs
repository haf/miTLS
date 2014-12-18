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

let fixedPadSize id =
        let authEnc = id.aeAlg in
        match authEnc with
        | MACOnly _ | AEAD(_,_) -> 0
        | MtE(enc,_) ->
            match enc with
            | Stream_RC4_128 -> 0
            | CBC_Stale(_) | CBC_Fresh(_) -> 1

let maxPadSize id =
        let authEnc = id.aeAlg in
        match authEnc with
        | MACOnly _ | AEAD(_,_) -> 0
        | MtE(enc,_) ->
                match enc with
                | Stream_RC4_128 -> 0
                | CBC_Stale(alg) | CBC_Fresh(alg) ->
                    match id.pv with
                    | SSL_3p0 -> blockSize alg
                    | TLS_1p0 | TLS_1p1 | TLS_1p2 -> 256

let minimalPadding e len =
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly _ | AEAD(_,_) -> fixedPadSize e
    | MtE(enc,_) ->
        match enc with
        | Stream_RC4_128 -> fixedPadSize e
        | CBC_Stale(alg) | CBC_Fresh(alg) ->
            let bs = blockSize alg in
            let lp = (len % bs) in
            let p = bs - lp in
            if p < 0 then
                Error.unreachable ""
            else p

//@ From plaintext range to ciphertext length
let targetLength e (rg:range) =
    let (_,h) = rg in
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly macAlg | MtE(Stream_RC4_128,macAlg)
    | MtE(CBC_Stale(_),macAlg) | MtE(CBC_Fresh(_),macAlg) ->
        let macLen = macSize macAlg in
        let ivL = ivSize e in
        let prePad = h + macLen in
        let padLen = minimalPadding e prePad in
        let res = ivL + prePad + padLen in
        if res > max_TLSCipher_fragment_length then
            Error.unexpected "[targetLength] given an invalid input range."
        else
            res
    | AEAD(aeadAlg,_) ->
        let ivL = aeadRecordIVSize aeadAlg in
        let tagL = aeadTagSize aeadAlg in
        let fp = fixedPadSize e in // 0, by refinement
        let res = ivL + h + fp + tagL in
        if res > max_TLSCipher_fragment_length then
            Error.unexpected "[targetLength] given an invalid input range."
        else
            res

let minMaxPad (i:id) =
    let maxPad = maxPadSize i in
    let fp = fixedPadSize i in
    (fp,maxPad)

//@ From ciphertext length to (maximal) plaintext range
let cipherRangeClass (e:id) tlen =
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly _ | MtE(Stream_RC4_128,_)
    | MtE(CBC_Fresh(_),_) | MtE(CBC_Stale(_),_) ->
        let macSize = macSize (macAlg_of_id e) in
        let ivL = ivSize e in
        let (minPad,maxPad) = minMaxPad e in
        let max = tlen - ivL - macSize - minPad in
        if max < 0 then
            Error.unexpected "[cipherRangeClass] the given tlen should be of a valid ciphertext"
        else
            let min = tlen - ivL - macSize - maxPad in
            if min < 0 then
                (0,max)
            else
                (min,max)
    | AEAD(aeadAlg,_) ->
        let ivL = aeadRecordIVSize aeadAlg in
        let tagL = aeadTagSize aeadAlg in
        let (minPad,maxPad) = minMaxPad e in
        let max = tlen - ivL - tagL - minPad in
        if max < 0 then
            Error.unexpected "[cipherRangeClass] the given tlen should be of a valid ciphertext"
        else
            let min = tlen - ivL - tagL - maxPad in
            if min < 0 then
                (0,max)
            else
                (min,max)

let rangeClass (e:id) (r:range) =
    let tlen = targetLength e r in
    cipherRangeClass e tlen
