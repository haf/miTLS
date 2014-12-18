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

module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream
open Error
open TLSError

#if ideal
type fpred = DeltaFragment of epoch * stream * range * delta
#endif

type preFragment = {frag: epoch * stream * delta}
type fragment = preFragment
type plain = fragment

let fragment e s r d =
    let i = id e in
    let f = {frag = e,s,d} in
    #if ideal
    Pi.assume (DeltaFragment(e,s,r,d));
    #endif
    let s' = append e s r d in
    (f,s')

let check (e:epoch) (e':epoch) = ()

let delta e s r f =
    let (e',s',d) = f.frag in
    // the following idealization is reindexing.
    #if ideal
    if auth e then
      // typechecking relies on e = e' & s = s':
      // they both follow from Auth(e), implying Sent(e,s,r,f) hence ?d. f.frag = (e,s,d)
      let s'' = append e s r d in
      (d,s'')
    else
      // we coerce d to the local epoch

      let raw = deltaRepr e' s' r d in
      let d' = deltaPlain e s r raw in
      let s'' = append e s r d' in
      (d',s'')
    #else
      // we could skip this append
      let s'' = append e s r d in
      (d,s'')
    #endif

let plain i r b =
  let e = TLSInfo.unAuthIdInv i in
  let s = DataStream.init e in
  let d = DataStream.deltaPlain e s r b in
  {frag = (e,s,d)}

let repr (i:id) r f =
  let (e',s,d) = f.frag in
  DataStream.deltaRepr e' s r d

let makeExtPad (i:id) (r:range) (f:fragment) =
#if TLSExt_extendedPadding
    if TLSExtensions.hasExtendedPadding i then
        let (e',s,d) = f.frag in

        let b = DataStream.deltaBytes e' s r d in
        let len = length b in
        let pad = extendedPad i r len in
        let padded = pad@|b in
        let d = DataStream.createDelta e' s r padded in
        {frag = (e',s,d)}
    else
#endif
        f

let parseExtPad (i:id) (r:range) (f:fragment) : Result<fragment> =
#if TLSExt_extendedPadding
    if TLSExtensions.hasExtendedPadding i then
        let (e',s,d) = f.frag in
        let b = DataStream.deltaBytes e' s r d in
        match TLSConstants.vlsplit 2 b with
        | Error(x) -> Error(x)
        | Correct(res) ->
            let (_,b) = res in
            let d = DataStream.createDelta e' s r b in
            correct ({frag = (e',s,d)})
    else
#endif
        correct f

#if ideal
let widen (i:id) (r0:range) (f0:fragment) =
    let r1 = rangeClass i r0 in
    let (e,s,d0) = f0.frag in
    let d1 = DataStream.widen e s r0 r1 d0 in
    let (f1,_) = fragment e s r1 d1 in
    f1
#endif
