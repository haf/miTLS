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

module StatefulPlain
open Bytes
open Error
open TLSConstants
open TLSInfo
open Range

type adata = bytes

let makeAD e ct =
    let si = epochSI(e) in
    let pv = si.protocol_version in
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0
    then bct
    else bct @| bver

let parseAD e ad =
    let si = epochSI(e) in
    let pv = si.protocol_version in
    if pv = SSL_3p0 then
        match parseCT ad with
        | Error(x,y) -> unexpectedError "[parseAD] should never parse failing"
        | Correct(ct) -> ct
    else
        if length ad = 3 then
            let (bct, bver) = Bytes.split ad 1 in
            match parseCT bct with
            | Error(x,y) -> unexpectedError "[parseAD] should never parse failing"
            | Correct(ct) ->
                match parseVersion bver with
                | Error(x,y) -> unexpectedError "[parseAD] should never parse failing"
                | Correct(ver) ->
                    if pv <> ver then
                        unexpectedError "[parseAD] should never parse failing"
                    else ct
        else
            unexpectedError "[parseAD] should never parse failing"

type fragment = {contents: TLSFragment.fragment}

type prehistory = (adata * range * fragment) list
type history = (nat * prehistory)

type plain = fragment

let consHistory (e:epoch) (h:prehistory) d r f = (d,r,f)::h

let emptyHistory (e:epoch): history = (0,[])
let extendHistory (e:epoch) d (sh:history) (r:range) f =
  let (seqn,h) = sh in
  let s' = seqn+1 in
  let nh = consHistory e h d r f in
  let res = (s',nh) in
  res

let plain (e:epoch) (h:history) (ad:adata) (r:range) (b:bytes) =
    let h = TLSFragment.emptyHistory e
    let ct = parseAD e ad in
    {contents = TLSFragment.plain e ct h r b}
let reprFragment (e:epoch) (ad:adata) (r:range) (f:plain) =
    let ct = parseAD e ad in
    let x = f.contents in
    TLSFragment.reprFragment e ct r x
let repr e (h:history) ad r f = reprFragment e ad r f

let RecordPlainToStAEPlain (e:epoch) (ct:ContentType) (ss:TLSFragment.history) (st:history) (rg:range) f = {contents = f}

let StAEPlainToRecordPlain (e:epoch) (ct:ContentType) (ss:TLSFragment.history) (st:history) (rg:range) f = f.contents

#if ideal
let widen e ad r f =
    let ct = parseAD e ad in
    let f1 = TLSFragment.widen e ct r f.contents in
    {contents = f1}
#endif
