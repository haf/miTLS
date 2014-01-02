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
open TLSInfo
open TLSConstants
open Range

#if verify
type preds = | CipherRange of epoch * range * nat
#endif

type plain =
    {plain: LHAEPlain.plain;
     tag:   MAC.tag;
     ok:    bool}

#if ideal
let zeros rg = let _,max = rg in createBytes max 0
#endif

let payload (e:epoch) (rg:range) ad f =
  // After applying CPA encryption for ENC,
  // we access the fragment bytes only at unsafe indexes, and otherwise use some zeros
  #if ideal
  if safe e then
    zeros rg
  else
  #endif
    LHAEPlain.repr e ad rg f

let macPlain (e:epoch) (rg:range) ad f =
    let b = payload e rg ad f
    ad @| vlbytes 2 b

let mac e k ad rg plain =
    let text = macPlain e rg ad plain in
    let tag  = MAC.Mac e k text in
    {plain = plain;
     tag = tag;
     ok = true
    }

let verify e k ad rg plain =
    let si = epochSI(e) in
    let pv = si.protocol_version in
    let f = plain.plain in
    let text = macPlain e rg ad f in
    let tag  = plain.tag in
    match pv with
//#begin-separate_err
    | SSL_3p0 | TLS_1p0 ->
        (*@ SSL3 and TLS1 enable both timing and error padding oracles. *)
        if plain.ok then
          if MAC.Verify e k text tag then
            correct f
          else
              let reason = "" in
              Error(AD_bad_record_mac,reason)
        else
           let reason = "" in
           Error(AD_decryption_failed,reason)
//#end-separate_err //#begin-uniform_err
    | TLS_1p1 | TLS_1p2 ->
        (*@ Otherwise, we implement standard mitigation for padding oracles.
            Still, we note a small timing leak here:
            The time to verify the mac is linear in the plaintext length. *)
        if MAC.Verify e k text tag then
          if plain.ok
            then correct f
          else
              let reason = "" in
              Error(AD_bad_record_mac,reason)
        else
           let reason = "" in
           Error(AD_bad_record_mac,reason)
//#end-uniform_err

let encodeNoPad (e:epoch) (tlen:nat) rg (ad:LHAEPlain.adata) data tag =
    let b = payload e rg ad data in
    let (_,h) = rg in
    if h <> length b then
        Error.unexpectedError "[encodeNoPad] invoked on an invalid range."
    else
    let payload = b @| tag
    if length payload <> tlen then
        Error.unexpectedError "[encodeNoPad] Internal error."
    else
        payload

let pad (p:int)  = createBytes p (p-1)

let encode (e:epoch) (tlen:nat) rg (ad:LHAEPlain.adata) data tag =
    let b = payload e rg ad data in
    let lb = length b in
    let lm = length tag in
    let ivL = ivSize e in
    let pl = tlen - lb - lm - ivL
    if pl > 0 && pl <= 256 then

        let payload = b @| tag @| pad pl
        if length payload <> tlen - ivL then
            Error.unexpectedError "[encode] Internal error."
        else
            payload
    else
        unexpectedError "[encode] Internal error."

let decodeNoPad e (ad:LHAEPlain.adata) rg tlen pl =
    let plainLen = length pl in
    if plainLen <> tlen then
        Error.unexpectedError "[decodeNoPad] wrong target length given as input argument."
    else
    let si = epochSI(e) in
    let maclen = macSize (macAlg_of_ciphersuite si.cipher_suite si.protocol_version) in
    let payloadLen = plainLen - maclen in
    let (frag,tag) = Bytes.split pl payloadLen in
    let aeadF = LHAEPlain.plain e ad rg frag in
    {plain = aeadF;
     tag = tag;
     ok = true}

let decode e (ad:LHAEPlain.adata) rg (tlen:nat) pl =
    let si = epochSI(e) in
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite si.protocol_version) in
    let pLen = length pl in
    let padLenStart = pLen - 1 in
    let (tmpdata, padlenb) = Bytes.split pl padLenStart in
    let padlen = int_of_bytes padlenb in
    let padstart = pLen - padlen - 1 in
    let macstart = pLen - macSize - padlen - 1 in
    let alg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match alg with
    | Stream_RC4_128 -> unreachable "[decode] invoked on stream cipher"
    | CBC_Stale(encAlg) | CBC_Fresh(encAlg) ->
    let bs = blockSize encAlg in
    if padstart < 0 || macstart < 0 then
        (*@ Evidently padding has been corrupted, or has been incorrectly generated *)
        (*@ Following TLS1.1 we fail later (see RFC5246 6.2.3.2 Implementation Note) *)
        let macstart = pLen - macSize - 1 in
        let (frag,tag) = split tmpdata macstart in
        let (l,h) = rg in
        let aeadF = LHAEPlain.plain e ad rg frag in
        { plain = aeadF;
            tag = tag;
            ok = false;
        }
    else
        let (data_no_pad,pad) = split tmpdata padstart in
        match si.protocol_version with
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
                let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = aeadF;
                    tag = tag;
                    ok = true;
                }
            else
                let macstart = pLen - macSize - 1 in
                let (frag,tag) = split tmpdata macstart in
                let (l,h) = rg in
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
                let (l,h) = rg in
                let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = aeadF;
                    tag = tag;
                    ok = true;
                }
            else
                let macstart = pLen - macSize - 1 in
                let (frag,tag) = split tmpdata macstart in
                let (l,h) = rg in
                let aeadF = LHAEPlain.plain e ad rg frag in
                { plain = aeadF;
                    tag = tag;
                    ok = false;
                }

let plain (e:epoch) ad tlen b =
  let si = epochSI(e) in
  let cs = si.cipher_suite in
  let pv = si.protocol_version in
  let authEnc = authencAlg_of_ciphersuite cs pv in
  let rg = cipherRangeClass e tlen in
  match authEnc with
    | MtE(Stream_RC4_128,_)
    | MACOnly _ ->
        decodeNoPad e ad rg tlen b
    | MtE(CBC_Stale(_),_)
    | MtE(CBC_Fresh(_),_) ->
        decode e ad rg tlen b

//  | GCM _ ->
    | _ -> unexpectedError "[Encode.plain] incompatible ciphersuite given."

let repr (e:epoch) ad rg pl =
  let si = epochSI(e) in
  let cs = si.cipher_suite in
  let pv = si.protocol_version in
  let authEnc = authencAlg_of_ciphersuite cs pv in
  let lp = pl.plain in
  let tg = pl.tag in
  let tlen = targetLength e rg in
  match authEnc with
    | MtE(Stream_RC4_128,_)
    | MACOnly _ ->
        encodeNoPad e tlen rg ad lp tg
    | MtE(CBC_Stale(_),_)
    | MtE(CBC_Fresh(_),_) ->
        encode e tlen rg ad lp tg
//  | GCM _ ->
    | _ -> unexpectedError "[Encode.repr] incompatible ciphersuite given."
