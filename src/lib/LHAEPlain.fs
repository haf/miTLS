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

module LHAEPlain
open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo
open Range

type adata = bytes

let makeAD (i:id) ((seqn,h):StatefulPlain.history) ad =
    let bn = bytes_of_seq seqn in
    bn @| ad

// We statically know that ad is big enough
let parseAD (i:id) ad =
    let (snb,ad) = Bytes.split ad 8 in
    ad

type fragment = {contents:StatefulPlain.fragment}
type plain = fragment

let plain (i:id) (ad:adata) (rg:range) b =
    let ad = parseAD i ad in
    let h = StatefulPlain.emptyHistory i in
    let p = StatefulPlain.plain i h ad rg b in
    {contents =  p}

let reprFragment (i:id) (ad:adata) (rg:range) p =
    let ad = parseAD i ad in
    StatefulPlain.reprFragment i ad rg p.contents

let repr i ad rg p = reprFragment i ad rg p

let StatefulPlainToLHAEPlain (i:id) (h:StatefulPlain.history)
    (ad:StatefulPlain.adata) (ad':adata) (r:range) f = {contents = f}
let LHAEPlainToStatefulPlain (i:id) (h:StatefulPlain.history)
    (ad:StatefulPlain.adata) (ad':adata) (r:range) f = f.contents

let makeExtPad id ad rg p =
    let ad = parseAD id ad in
    let c = p.contents in
    let c = StatefulPlain.makeExtPad id ad rg c in
    {contents = c}

let parseExtPad id ad rg p =
    let ad = parseAD id ad in
    let c = p.contents in
    match StatefulPlain.parseExtPad id ad rg c with
    | Error(x) -> Error(x)
    | Correct(c) -> correct ({contents = c})

#if ideal
let widen i ad r f =
    let ad' = parseAD i ad in
    let f' = StatefulPlain.widen i ad' r f.contents in
    {contents = f'}
#endif
