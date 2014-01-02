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

module AEAD_GCM

open Bytes
open Range
open TLSInfo
open Error
open TLSError
open TLSConstants

type cipher = bytes
type key = {kb:bytes}
type iv = {ivb:bytes}
type counter = nat

type state = {key:key;
              iv:iv;
              counter:counter}

type encryptor = state
type decryptor = state

let GEN (ki:id) : encryptor * decryptor = failwith "verification only"

let COERCE (ki:id) (rw:rw) k iv =
    let key = {kb=k} in
    let iv = {ivb=iv} in
    {key = key;
     iv = iv;
     counter = 0}

let LEAK (id:id) (rw:rw) s =
    let key = s.key in
    let kb = key.kb in
    let iv = s.iv in
    let ivb = iv.ivb in
    (kb @| ivb)

let ENC (id:id) state (adata:LHAEPlain.adata) (rg:range) p =
    let k = state.key in
    let ivb = state.iv.ivb in
    let cb = TLSConstants.bytes_of_seq state.counter in
    let iv = ivb @| cb in

    let text = LHAEPlain.repr id adata rg p in
    let tLen = length text in
    let tLenB = bytes_of_int 2 tLen in
    let ad = adata @| tLenB in
    let cipher = CoreCiphers.aes_gcm_encrypt k.kb iv ad text in

    let cipher = cb @| cipher in
    let newCounter = state.counter + 1 in
    let state = {state with counter = newCounter}
    (state,cipher)

let DEC (id:id) state (adata:LHAEPlain.adata) (rg:range) cipher =
    match id.aeAlg with
    | AEAD(aealg,_) ->
        let recordIVLen = aeadRecordIVSize aealg in
        let (explicit,cipher) = split cipher recordIVLen in
        let ivb = state.iv.ivb in
        let iv = ivb @| explicit in
        let tagLen = aeadTagSize aealg in
        let len = length cipher - tagLen in
        let lenB = bytes_of_int 2 len in
        let ad = adata @| lenB in
        let k = state.key in
        match CoreCiphers.aes_gcm_decrypt k.kb iv ad cipher with
        | None ->
           let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
        | Some(plain) ->
           let plain = LHAEPlain.plain id adata rg plain in
           correct (state,plain)
    | _ -> unexpected "[DEC] invoked on wrong algorithm"
