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

module Record

open Bytes
open Error
open TLSError
open TLSInfo
open TLSConstants
open Range

type ConnectionState =
    | NullState
    | SomeState of TLSFragment.history * StatefulLHAE.state

let someState (e:epoch) (rw:rw) h s = SomeState(h,s)

type sendState = ConnectionState
type recvState = ConnectionState

let initConnState (e:epoch) (rw:rw) s =
  let i = id e in
  let h = TLSFragment.emptyHistory e in
  someState e rw h s

let nullConnState (e:epoch) (rw:rw) = NullState

// packet format
let makePacket ct ver data =
    let l = length data in
    let bct  = ctBytes ct in
    let bver = versionBytes ver in
    let bl   = bytes_of_int 2 l in
    bct @| bver @| bl @| data

let parseHeader b =
    let (ct1,rem4) = split b 1 in
    let (pv2,len2) = split rem4 2 in
    match parseCT ct1 with
    | Error(z) -> Error(z)
    | Correct(ct) ->
    match TLSConstants.parseVersion pv2 with
    | Error(z) -> Error(z)
    | Correct(pv) ->
    let len = int_of_bytes len2 in
    if len <= 0 || len > max_TLSCipher_fragment_length then
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Wrong frgament length")
    else
        correct(ct,pv,len)

(* This replaces send. It's not called send,
   since it doesn't send anything on the network *)
let recordPacketOut e conn pv rg ct fragment =
    (* No need to deal with compression. It is handled internally by TLSPlain,
       when returning us the next (already compressed!) fragment *)

    let initEpoch = isInitEpoch e in
    match conn with
    | NullState when initEpoch = true ->
        let i = id e in // doesn't typechecke
        let payload = TLSFragment.reprFragment i ct rg fragment in
        let packet = makePacket ct pv payload in
        (conn,packet)
    | SomeState(history,state) when initEpoch = false ->
        let i = id e in
        let ad = StatefulPlain.makeAD i ct in
        let sh = StatefulLHAE.history i Writer state in
        let aeadF = StatefulPlain.RecordPlainToStAEPlain e ct ad history sh rg fragment in
        let (state,payload) = StatefulLHAE.encrypt i state ad rg aeadF in
        let history = TLSFragment.extendHistory e ct history rg fragment in
        let packet = makePacket ct pv payload in
        (SomeState(history,state),
         packet)
    | _ -> unexpected "[recordPacketOut] Incompatible ciphersuite and key type"

let recordPacketIn e conn ct payload =
    let initEpoch = isInitEpoch e in
    match conn with
    | NullState when initEpoch ->
        (let plen = length payload in
        let rg = (plen,plen) in
        let i = id e in
        let msg = TLSFragment.fragment i ct rg payload in
        correct(conn,rg,msg))
    | SomeState(history,state) when initEpoch = false ->
        (let i = id e in
        let ad = StatefulPlain.makeAD i ct in
        let decr = StatefulLHAE.decrypt i state ad payload in
        match decr with
        | Error(z) -> Error(z)
        | Correct (decrRes) ->
            let (newState, rg, plain) = decrRes in
            let oldH = StatefulLHAE.history i Reader state in
            let msg = StatefulPlain.StAEPlainToRecordPlain e ct ad history oldH rg plain in
            let history = TLSFragment.extendHistory e ct history rg msg in
            let st' = someState e Reader history newState in
            correct(st',rg,msg))
    | _ -> unexpected "[recordPacketIn] Incompatible ciphersuite and key type"

let history (e:epoch) (rw:rw) s =
    match s with
    | NullState ->
        let i = id e in
        TLSFragment.emptyHistory e
    | SomeState(h,_) -> h
