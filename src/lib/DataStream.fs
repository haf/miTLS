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

module DataStream
open TLSConstants
open TLSInfo
open Bytes
open Error
open Range

let min (a:nat) (b:nat) =
    if a <= b then a else b
let max (a:nat) (b:nat) =
    if a >= b then a else b

let splitRange ki r =
    let (l,h) = r in
    let si = epochSI(ki) in
    let cs = si.cipher_suite in
    let FS = TLSInfo.fragmentLength in
    let PS = maxPadSize si in
    if PS = 0 then
        if l<>h then
            unexpectedError "[splitRange] Incompatible range provided"
        else
            let len = min h FS in
            let r0 = (len,len) in
            let r1 = (l-len,h-len) in
            (r0,r1)
    else
        let encAlg = encAlg_of_ciphersuite cs si.protocol_version in
        match encAlg with
        | Stream_RC4_128 -> unexpectedError "[splitRange] Stream ciphers do not support pad"
        | CBC_Stale(alg) | CBC_Fresh(alg) ->
            let BS = blockSize alg in
            let t  = macSize (TLSConstants.macAlg_of_ciphersuite cs si.protocol_version) in
            if FS < PS || PS < BS then
                unexpectedError "[splitRange] Incompatible fragment size, padding size and block size"
            else
                if l >= FS then
                    let r0 = (FS,FS) in
                    let r1 = (l-FS,h-FS) in
                    (r0,r1)
                else
                    let z0 = PS - ((PS + t + 1) % BS) in
                    let zl = PS - ((l + PS + t + 1) % BS) in
                    if l = 0 then
                        let p = h-l in
                        let fh = min p z0 in
                        let r0 = (0,fh) in
                        let r1 = (0,h-fh) in
                        (r0,r1)
                    else
                        let p = (h-l) % z0 in
                        if (p <= zl) && (l+p <= FS) then
                            let r0 = (l,l+p) in
                            let r1 = (0,h-(l+p)) in
                            (r0,r1)
                        else
                            let r0 = (l,l) in
                            let r1 = (0,h-l) in
                            (r0,r1)

type stream = {sb: bytes list}
type delta = {contents: rbytes}

let createDelta (ki:epoch) (s:stream) (r:range) (b:bytes) = {contents = b}
let deltaBytes  (ki:epoch) (s:stream) (r:range) (d:delta) = d.contents
let deltaPlain  (ki:epoch) (s:stream) (r:range) (b:rbytes) = {contents = b}
let deltaRepr   (ki:epoch) (s:stream) (r:range) (d:delta) = d.contents

// ghost
type es = EmptyStream of epoch

let init (ki:epoch) = {sb = []}

let append (ki:epoch) (s:stream) (r:range) (d:delta) =
  {sb = d.contents :: s.sb}

let split (ki:epoch) (s:stream)  (r0:range) (r1:range) (d:delta) =
  let (_,h0) = r0 in
  let (l1,_) = r1 in
  let len = length d.contents in
  let n = if h0 < (len - l1) then h0 else len - l1
  let (sb0,sb1) = Bytes.split d.contents n in
  ({contents = sb0},{contents = sb1})

#if ideal
let widen (ki:epoch) (s:stream) (r0:range) (r1:range) (d:delta) = let b = d.contents in {contents = b}
#endif
