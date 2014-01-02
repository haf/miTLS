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

module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream

type fragment = {frag: stream * delta}
#if verify
type fpred = DeltaFragment of epoch * stream * range * delta
#endif
type plain = fragment

let fragment ki s r d =
    let f = {frag = s,d} in
#if verify
    Pi.assume (DeltaFragment(ki,s,r,d));
#endif
    let s' = append ki s r d in
    (f,s')

let delta ki s r f =
    let (s',d) = f.frag in
    let s'' = append ki s r d in
    (d,s'')

let delta' ki s r f =
    let (s',d) = f.frag in
    let b = DataStream.deltaRepr ki s' r d in
    let d = DataStream.deltaPlain ki s r b in
    let s'' = append ki s r d in
    (d,s'')

let plain ki r b =
  let s = DataStream.init ki in
  let d = DataStream.deltaPlain ki s r b in
  {frag = (s,d)}

let repr ki r f =
  let (s,d) = f.frag in
  DataStream.deltaRepr ki s r d

#if ideal
let widen (e:epoch) (r0:range) (f0:fragment) =
    let r1 = rangeClass e r0 in
    let (s,d0) = f0.frag in
    let d1 = DataStream.widen e s r0 r1 d0 in
    let (f1,_) = fragment e s r1 d1 in
    f1
#endif
