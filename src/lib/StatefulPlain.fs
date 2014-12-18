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

module StatefulPlain
open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo
open Range

type cadata = cbytes
type adata = bytes

let makeAD (i:id) ct =
    let pv   = pv_of_id i
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0
    then bct
    else bct @| bver

let parseAD (i:id) ad =
    let pv = pv_of_id i
    if pv = SSL_3p0 then
        let pct = parseCT ad in
        match pct with
        | Error x -> unexpected "[parseAD] should never parse failing"
        | Correct(ct) -> ct
    else
        if length ad = 3 then
            let (bct, bver) = Bytes.split ad 1 in
            match parseCT bct with
            | Error x -> unexpected "[parseAD] should never parse failing"
            | Correct(ct) ->
                match parseVersion bver with
                | Error x -> unexpected "[parseAD] should never parse failing"
                | Correct(ver) ->
                    if pv <> ver then
                        unexpected "[parseAD] should never parse failing"
                    else ct
        else
            unexpected "[parseAD] should never parse failing"

type fragment = {contents: TLSFragment.fragment}

type prehistory = list<(adata * range * fragment)>
type history = (nat * prehistory)

type plain = fragment

let consHistory (i:id) (h:prehistory) (d:adata) (r:range) (f:fragment) =
#if ideal
    (d,r,f)::h
#else
    h
#endif

let emptyHistory (i:id): history = (0,[])
let extendHistory (i:id) d (sh:history) (r:range) f =
  let (seqn,h) = sh in
  let s' = seqn+1 in
  let nh = consHistory i h d r f in
  let res = (s',nh) in
  res

let plain (i:id) (h:history) (ad:adata) (r:range) (b:bytes) =

    let ct = parseAD i ad in
    {contents = TLSFragment.fragment i ct r b}
let reprFragment (i:id) (ad:adata) (r:range) (f:plain) =
    let ct = parseAD i ad in
    let x = f.contents in
    TLSFragment.reprFragment i ct r x
let repr i (h:history) ad r f = reprFragment i ad r f

let makeExtPad (i:id) (ad:adata) (r:range) f =
    let ct = parseAD i ad in
    let p = f.contents in
    let p = TLSFragment.makeExtPad i ct r p in
    {contents = p}

let parseExtPad (i:id) (ad:adata) (r:range) f =
    let ct = parseAD i ad in
    let p = f.contents in
    match TLSFragment.parseExtPad i ct r p with
    | Error(x) -> Error(x)
    | Correct(p) -> correct ({contents = p})

#if ideal
let widen i ad r f =
    let ct = parseAD i ad in
    let f1 = TLSFragment.widen i ct r f.contents in
    {contents = f1}
#endif

let RecordPlainToStAEPlain (e:epoch) (ct:ContentType) (ad:adata) (h:TLSFragment.history) (sh:history) (rg:range) f = {contents = f}
let StAEPlainToRecordPlain (e:epoch) (ct:ContentType) (ad:adata) (h:TLSFragment.history) (sh:history) (rg:range) f = f.contents
