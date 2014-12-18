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

#light "off"

module DataStream
open TLSConstants
open TLSInfo
open Bytes
open Error
open TLSError
open Range

let min (a:nat) (b:nat) =
    if a <= b then a else b

let maxLHPad id len =
    let FS = TLSInfo.fragmentLength in
    let PS = maxPadSize id in
    let thisPad = min PS (FS-len) in
    let authEnc = id.aeAlg in
    match authEnc with
    | MtE(encAlg,macAlg) ->
        (match encAlg with
        | Stream_RC4_128 -> thisPad
        | CBC_Stale(alg) | CBC_Fresh(alg) ->
            let BS = blockSize alg in
            let MS = macSize macAlg in
            let PL = fixedPadSize id in
            let overflow = (len + thisPad + MS + PL) % BS in
            if overflow > thisPad then
                thisPad
            else
                thisPad - overflow)
    | AEAD(_,_) ->
        thisPad
    | _ -> unexpected "[maxLHPad] invoked on an invalid ciphersuite"

let splitRange ki r =
    let (l,h) = r in
    let si = epochSI(ki) in
    let cs = si.cipher_suite in
    let FS = TLSInfo.fragmentLength in
    let id = id ki in
    let PS = maxPadSize id in
    if PS = 0 || l = h then
        // no LH to do
        if l<>h then
            unexpected "[splitRange] Incompatible range provided"
        else
            let len = min h FS in
            let r0 = (len,len) in
            let r1 = (l-len,h-len) in
            (r0,r1)
    else
        if l >= FS then
            let r0 = (FS,FS) in
            let r1 = (l-FS,h-FS) in
            (r0,r1)
        else
            let allPad = maxLHPad id l in
            let allPad = min allPad (h-l) in
            if l+allPad > FS then
                unexpected "[splitRange] Computing range over fragment size"
            else
                let r0 = (l,l+allPad) in
                let r1 = (0,h - (l+allPad)) in
                (r0,r1)

type stream = {sb: list<cbytes>}
type delta = {contents: rbytes}

let createDelta (ki:epoch) (s:stream) (r:range) (b:bytes) = {contents = b}
let deltaBytes  (ki:epoch) (s:stream) (r:range) (d:delta) = d.contents
let deltaPlain  (ki:epoch) (s:stream) (r:range) (b:rbytes) = {contents = b}
let deltaRepr   (ki:epoch) (s:stream) (r:range) (d:delta) = d.contents

// ghost
type es = EmptyStream of epoch

let init (ki:epoch) = {sb = []}

let append (ki:epoch) (s:stream) (r:range) (d:delta) =
#if ideal
    let dc = d.contents in
    let c = cbytes dc in
    {sb = c :: s.sb}
#else
    s
#endif

let split (ki:epoch) (s:stream)  (r0:range) (r1:range) (d:delta) =
  let (_,h0) = r0 in
  let (l1,_) = r1 in
  let len = length d.contents in
  let n = if h0 < (len - l1) then h0 else len - l1 in
  let (sb0,sb1) = Bytes.split d.contents n in
  ({contents = sb0},{contents = sb1})

#if ideal
let widen (ki:epoch) (s:stream) (r0:range) (r1:range) (d:delta) = let b = d.contents in {contents = b}
#endif
