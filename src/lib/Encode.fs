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

module Encode

open Bytes
open Error
open TLSError
open TLSInfo
open TLSConstants
open Range

type plain =
    {plain: LHAEPlain.plain;
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

let macPlain_bytes (e:id) (rg:range) ad b =
    ad @| vlbytes 2 b

let macPlain (e:id) (rg:range) ad f =
    let b = payload e rg ad f in
    macPlain_bytes e rg ad b

#if ideal
type maconly_entry = id * LHAEPlain.adata * range * nat * bytes * bytes * LHAEPlain.plain * MAC.tag
let maconly_log = ref ([]:list<maconly_entry>)
let rec maconly_mem i ad cl pl text tag (xs:list<maconly_entry>) =
    match xs with
    | (i', ad', rg', cl', pl', text', p', tag')::_
        when i=i' && ad=ad' && cl=cl' && pl=pl' && text=text' && tag=tag' -> let x = (rg',p') in Some x
    | _::xs -> maconly_mem i ad cl pl text tag xs
    | [] -> None
#endif

let mac e k ad rg plain =
    let plain = LHAEPlain.makeExtPad e ad rg plain in
    let text = macPlain e rg ad plain in
    let tag  = MAC.Mac e k text in
#if ideal
    (* For MACOnly ciphersuites where AuthId holds, we store the plain and
     * the tag in the MACOnly log *)
    let e_aealg = e.aeAlg in
    (match (authId e, e_aealg) with
    | (true,MACOnly(_)) ->
        let tlen = targetLength e rg in
        let pl = payload e rg ad plain in
        maconly_log := (e,ad,rg,tlen,pl,text,plain,tag)::!maconly_log
    | (_,_) -> ());
#endif
    {plain = plain;
     tag = tag;
     ok = true
    }

let verify_MACOnly (e:id) k ad rg (cl:nat) b tag =
    let text = macPlain_bytes e rg ad b in
    if MAC.Verify e k text tag then
#if ideal
        if authId e then
            match maconly_mem e ad cl b text tag !maconly_log with
            | Some(x) ->
                let (rg',p') = x in
                let p = LHAEPlain.widen e ad rg' p' in
                let rg = rangeClass e rg' in
                correct (rg,p)
            | None ->
                let reason = perror __SOURCE_FILE__ __LINE__ "" in
                Error(AD_bad_record_mac,reason)
        else
#endif
            let p = LHAEPlain.plain e ad rg b in
            correct (rg,p)
    else
        let reason = perror __SOURCE_FILE__ __LINE__ "" in
        Error(AD_bad_record_mac,reason)

let verify (e:id) k ad rg plain : Result<LHAEPlain.plain> =
    let f = plain.plain in
    let text = macPlain e rg ad f in
    let tag  = plain.tag in
        (*@ We implement standard mitigation for padding oracles.
            Still, we note a small timing leak here:
            The time to verify the mac is linear in the plaintext length. *)
        if MAC.Verify e k text tag then
          if plain.ok then
            match LHAEPlain.parseExtPad e ad rg f with
            | Error(x) ->
                let reason = "" in
                Error(AD_bad_record_mac,reason)
            | Correct(f) -> correct f
          else
              let reason = "" in
              Error(AD_bad_record_mac,reason)
        else
           let reason = "" in
           Error(AD_bad_record_mac,reason)

let encodeNoPad (e:id) (tlen:nat) (rg:range) (ad:LHAEPlain.adata) data tag =
    let b = payload e rg ad data in
    let (_,h) = rg in
    if
#if TLSExt_extendedPadding
        (not (TLSExtensions.hasExtendedPadding e)) &&
#endif
        h <> length b then
        Error.unexpected "[encodeNoPad] invoked on an invalid range."
    else
    let payload = b @| tag in
    if length payload <> (tlen - ivSize e) then
        Error.unexpected "[encodeNoPad] Internal error."
    else
        payload

let pad (p:int)  = createBytes p (p-1)

let encode (e:id) (tlen:nat) (rg:range) (ad:LHAEPlain.adata) data tag =
    let b = payload e rg ad data in
    let lb = length b in
    let lm = length tag in
    let ivL = ivSize e in
    let pl = tlen - lb - lm - ivL in
    if pl > 0 && pl <= 256 then

        let payload = b @| tag @| pad pl in
        if length payload <> tlen - ivL then
            Error.unexpected "[encode] Internal error."
        else
            payload
    else
        unexpected "[encode] Internal error."

let decodeNoPad_bytes (e:id) (ad:LHAEPlain.adata) (rg:range) tlen pl =
    let plainLen = length pl in
    if plainLen <> (tlen - ivSize e) then
        Error.unreachable "[decodeNoPad] wrong target length given as input argument."
    else
    let macAlg = macAlg_of_id e in
    let maclen = macSize macAlg in
    let payloadLen = plainLen - maclen in
    Bytes.split pl payloadLen

let decodeNoPad (e:id) (ad:LHAEPlain.adata) (rg:range) tlen pl =
    let frag,tag = decodeNoPad_bytes e ad rg tlen pl in
    let aeadF = LHAEPlain.plain e ad rg frag in
    {plain = aeadF;
     tag = tag;
     ok = true}

let decode (e:id) (ad:LHAEPlain.adata) (rg:range) (tlen:nat) pl =
    let a = e.aeAlg in
    let macSize = macSize (macAlg_of_aeAlg a) in
    let fp = fixedPadSize e in
    let pLen = length pl in
    let padLenStart = pLen - fp in
    let (tmpdata, padlenb) = Bytes.split pl padLenStart in
    let padlen = int_of_bytes padlenb in
    let padstart = pLen - padlen - fp in
    let macstart = pLen - macSize - padlen - fp in
    let encAlg = encAlg_of_aeAlg a in
    match encAlg with
    | Stream_RC4_128 -> unreachable "[decode] invoked on stream cipher"
    | CBC_Stale(encAlg) | CBC_Fresh(encAlg) ->
    let bs = blockSize encAlg in
    if padstart < 0 || macstart < 0 then
        (*@ Evidently padding has been corrupted, or has been incorrectly generated *)
        (*@ Following TLS1.1 we fail later (see RFC5246 6.2.3.2 Implementation Note) *)
        let macstart = pLen - macSize - fp in
        let (frag,tag) = split tmpdata macstart in
        let aeadF = LHAEPlain.plain e ad rg frag in
        { plain = aeadF;
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
                let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = aeadF;
                    tag = tag;
                    ok = true;
                }
            else
                let macstart = pLen - macSize - fp in
                let (frag,tag) = split tmpdata macstart in
                let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = aeadF;
                    tag = tag;
                    ok = false;
                }
        | SSL_3p0 ->
            (*@ Padding is random in SSL_3p0, no check to be done on its content.
                However, its length should be at most one bs
                (See sec 5.2.3.2 of SSL 3 draft). Enforce this check. *)
            if padlen < bs then
                let (frag,tag) = split data_no_pad macstart in
                let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = aeadF;
                    tag = tag;
                    ok = true;
                }
            else
                let macstart = pLen - macSize - fp in
                let (frag,tag) = split tmpdata macstart in
                let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = aeadF;
                    tag = tag;
                    ok = false;
                }

let plain (e:id) ad tlen b =
  let authEnc = e.aeAlg in
  let rg = cipherRangeClass e tlen in
  match authEnc with
    | MtE(Stream_RC4_128,_) ->
        decodeNoPad e ad rg tlen b
    | MtE(CBC_Stale(_),_)
    | MtE(CBC_Fresh(_),_) ->
#if TLSExt_extendedPadding
        if TLSExtensions.hasExtendedPadding e then
            decodeNoPad e ad rg tlen b
        else
#endif
            decode e ad rg tlen b
    | _ -> unexpected "[Encode.plain] incompatible ciphersuite given."

let repr (e:id) ad rg pl =
  let authEnc = e.aeAlg in
  let lp = pl.plain in
  let tg = pl.tag in
  let tlen = targetLength e rg in
  match authEnc with
    | MtE(Stream_RC4_128,_)
    | MACOnly _ ->
        encodeNoPad e tlen rg ad lp tg
    | MtE(CBC_Stale(_),_)
    | MtE(CBC_Fresh(_),_) ->
#if TLSExt_extendedPadding
        if TLSExtensions.hasExtendedPadding e then
            encodeNoPad e tlen rg ad lp tg
        else
#endif
            encode e tlen rg ad lp tg
    | _ -> unexpected "[Encode.repr] incompatible ciphersuite given."

#if ideal
let widen i ad r f =
    let p = LHAEPlain.widen i ad r f.plain in
    {plain = p;
     tag = f.tag;
     ok = f.ok}
#endif
