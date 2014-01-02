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

module Encode

open Bytes
open Error
open TLSError
open TLSInfo
open TLSConstants
open Range

#if verify
type preds = | CipherRange of id * range * nat
#endif

type plain =
    {plain: bytes;
     tag:   MAC.tag;
     ok:    bool}

#if ideal
let zeros (rg:range) = let _,max = rg in createBytes max 0
#endif

let payload (e:id) (rg:range) ad f =
  // After applying CPA encryption for ENC,
  // we access the fragment bytes only at unsafe indexes, and otherwise use some zeros
  #if ideal
  if safeId  e then
    zeros rg
  else
  #endif
    LHAEPlain.repr e ad rg f

let macPlain (e:id) (rg:range) ad b =
    ad @| vlbytes 2 b

let mac e k ad rg plain =
    let b = payload e rg ad plain in
    let text = macPlain e rg ad b in
    let tag  = MAC.Mac e k text in
    {plain = b;
     tag = tag;
     ok = true
    }

let verify (e:id) k ad rg plain =
    let f = plain.plain in
    let text = macPlain e rg ad f in
    let tag  = plain.tag in
        (*@ We implement standard mitigation for padding oracles.
            Still, we note a small timing leak here:
            The time to verify the mac is linear in the plaintext length. *)
        if MAC.Verify e k text tag then
          if plain.ok then
              match LHAEPlain.plain e ad rg f with
              | Error(x,y) ->
                // In extended padding, pading check has failed
                Error(x,y)
              | Correct(frag) -> correct frag
          else
              let reason = "" in
              Error(AD_bad_record_mac,reason)
        else
           let reason = "" in
           Error(AD_bad_record_mac,reason)

let encodeNoPad (e:id) (tlen:nat) rg (ad:LHAEPlain.adata) data tag =
    //let b = payload e rg ad data in
    let (_,h) = rg in
    if (not e.extPad) && h <> length data then
        Error.unexpected "[encodeNoPad] invoked on an invalid range."
    else
    let payload = data @| tag
    if length payload <> tlen then
        Error.unexpected "[encodeNoPad] Internal error."
    else
        payload

let pad (p:int)  = createBytes p (p-1)

let encode (e:id) (tlen:nat) rg (ad:LHAEPlain.adata) data tag =
    //let b = payload e rg ad data in
    let lb = length data in
    let lm = length tag in
    let ivL = ivSize e in
    let pl = tlen - lb - lm - ivL
    if pl > 0 && pl <= 256 then

        let payload = data @| tag @| pad pl
        if length payload <> tlen - ivL then
            Error.unexpected "[encode] Internal error."
        else
            payload
    else
        unexpected "[encode] Internal error."

let decodeNoPad (e:id) (ad:LHAEPlain.adata) rg tlen pl =
    let plainLen = length pl in
    if plainLen <> tlen then
        Error.unexpected "[decodeNoPad] wrong target length given as input argument."
    else
    let macAlg = macAlg_of_id e in
    let maclen = macSize macAlg in
    let payloadLen = plainLen - maclen in
    let (frag,tag) = Bytes.split pl payloadLen in
    //let aeadF = LHAEPlain.plain e ad rg frag in
    {plain = frag;
     tag = tag;
     ok = true}

let decode (e:id) (ad:LHAEPlain.adata) rg (tlen:nat) pl =
    let a = e.aeAlg
    let macSize = macSize (macAlg_of_aeAlg a) in
    let pLen = length pl in
    let padLenStart = pLen - 1 in
    let (tmpdata, padlenb) = Bytes.split pl padLenStart in
    let padlen = int_of_bytes padlenb in
    let padstart = pLen - padlen - 1 in
    let macstart = pLen - macSize - padlen - 1 in
    let encAlg = encAlg_of_aeAlg a
    match encAlg with
    | Stream_RC4_128 -> unreachable "[decode] invoked on stream cipher"
    | CBC_Stale(encAlg) | CBC_Fresh(encAlg) ->
    let bs = blockSize encAlg in
    if padstart < 0 || macstart < 0 then
        (*@ Evidently padding has been corrupted, or has been incorrectly generated *)
        (*@ Following TLS1.1 we fail later (see RFC5246 6.2.3.2 Implementation Note) *)
        let macstart = pLen - macSize - 1 in
        let (frag,tag) = split tmpdata macstart in
        let (l,h) = rg in
        //let aeadF = LHAEPlain.plain e ad rg frag in
        { plain = frag;
            tag = tag;
            ok = false;
        }
    else
        let (data_no_pad,pad) = split tmpdata padstart in
        match pv_of_id e with
        | TLS_1p0 | TLS_1p1 | TLS_1p2 ->
            (*@ We note the small timing leak here.
                The timing of the following two lines
                depends on padding length.
                We could mitigate it by implementing
                constant time comparison up to maximum padding length.*)
            let expected = createBytes padlen padlen in
            if equalBytes expected pad then
                let (frag,tag) = split data_no_pad macstart in
                let (l,h) = rg in
                //let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = frag;
                    tag = tag;
                    ok = true;
                }
            else
                let macstart = pLen - macSize - 1 in
                let (frag,tag) = split tmpdata macstart in
                let (l,h) = rg in
                //let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = frag;
                    tag = tag;
                    ok = false;
                }
        | SSL_3p0 ->
            (*@ Padding is random in SSL_3p0, no check to be done on its content.
                However, its length should be at most one bs
                (See sec 5.2.3.2 of SSL 3 draft). Enforce this check. *)
            if padlen < bs then
                let (frag,tag) = split data_no_pad macstart in
                let (l,h) = rg in
                //let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = frag;
                    tag = tag;
                    ok = true;
                }
            else
                let macstart = pLen - macSize - 1 in
                let (frag,tag) = split tmpdata macstart in
                let (l,h) = rg in
                //let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = frag;
                    tag = tag;
                    ok = false;
                }

let plain (e:id) ad tlen b =
  let authEnc = e.aeAlg
  let rg = cipherRangeClass e tlen in
  match authEnc with
    | MtE(Stream_RC4_128,_)
    | MACOnly _ ->
        decodeNoPad e ad rg tlen b
    | MtE(CBC_Stale(_),_)
    | MtE(CBC_Fresh(_),_) ->
        if e.extPad then
            decodeNoPad e ad rg tlen b
        else
            decode e ad rg tlen b

//  | GCM _ ->
    | _ -> unexpected "[Encode.plain] incompatible ciphersuite given."

let repr (e:id) ad rg pl =
  let authEnc = e.aeAlg
  let lp = pl.plain in
  let tg = pl.tag in
  let tlen = targetLength e rg in
  match authEnc with
    | MtE(Stream_RC4_128,_)
    | MACOnly _ ->
        encodeNoPad e tlen rg ad lp tg
    | MtE(CBC_Stale(_),_)
    | MtE(CBC_Fresh(_),_) ->
        if e.extPad then
            encodeNoPad e tlen rg ad lp tg
        else
            encode e tlen rg ad lp tg
//  | GCM _ ->
    | _ -> unexpected "[Encode.repr] incompatible ciphersuite given."
