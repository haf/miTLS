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

type fragment = {frag: rbytes}
type stream = {sb:bytes list}
type plain = fragment

let fragmentPlain (ki:epoch) (r:range) b = {frag = b}
let fragmentRepr (ki:epoch) (r:range) f = f.frag

let init (e:epoch) = {sb=[]}
let extend (e:epoch) (s:stream) (r:range) (f:fragment) =
#if ideal
    {sb = f.frag :: s.sb}
#else
    s
#endif

let reStream (e:epoch) (s:stream) (r:range) (p:plain) (s':stream) = p

#if ideal
let widen (e:epoch) (r0:range) (r1:range) (f0:fragment) =
    let b = f0.frag in {frag = b}
#endif
