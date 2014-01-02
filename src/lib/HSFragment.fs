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

module HSFragment
open Bytes
open TLSInfo
open Range
open Error
open TLSError

type fragment = {frag: rbytes}
type stream = {sb:bytes list}
type plain = fragment

let userPlain (id:id) (r:range) b = {frag = b}
let userRepr  (id:id) (r:range) f = f.frag

let fragmentPlain (ki:id) (r:range) b =
    if ki.extPad then
        match TLSConstants.vlsplit 2 b with
        | Error(x,y) -> Error(x,y)
        | Correct(res) ->
            let (_,b) = res in
            correct ({frag = b})
    else
        correct ({frag = b})

let fragmentRepr (ki:id) (r:range) f =
    let b = f.frag in
    if ki.extPad then
        let r = alignedRange ki r in
        let (_,h) = r in
        let plen = h - (length b) in
        let pad = createBytes plen 0 in
        let pad = TLSConstants.vlbytes 2 pad in
        pad @| b
    else
        b

let init (e:id) = {sb=[]}
let extend (e:id) (s:stream) (r:range) (f:fragment) =
#if ideal
    {sb = f.frag :: s.sb}
#else
    s
#endif

let reStream (e:id) (s:stream) (r:range) (p:plain) (s':stream) = p

#if ideal
let widen (e:id) (r0:range) (r1:range) (f0:fragment) =
    let b = f0.frag in {frag = b}
#endif
