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

module Record

open Bytes
open Error
open TLSInfo
open TLSConstants
open Range

type ConnectionState =
    | NullState
    | SomeState of TLSFragment.history * StatefulLHAE.state

let someState (ki:epoch) (rw:StatefulLHAE.rw) h s = SomeState(h,s)

type sendState = ConnectionState
type recvState = ConnectionState

let initConnState (ki:epoch) (rw:StatefulLHAE.rw) s =
  let eh = TLSFragment.emptyHistory ki in
  someState ki rw eh s

let nullConnState (ki:epoch) (rw:StatefulLHAE.rw) = NullState

// packet format
let makePacket ct ver data =
    let l = length data in
    let bct  = ctBytes ct in
    let bver = versionBytes ver in
    let bl   = bytes_of_int 2 l in
    bct @| bver @| bl @| data

let headerLength b =
    let (ct1,rem4) = split b 1  in
    let (pv2,len2) = split rem4 2 in
    let len = int_of_bytes len2 in
    // With a precise int/byte model,
    // no need to check len, since it's on 2 bytes and the max allowed value is 2^16.
    // Here we do a runtime check to get the same property statically
    if len <= 0 || len > max_TLSCipher_fragment_length then
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Wrong fragment length")
    else
        correct(len)

let parseHeader b =
    let (ct1,rem4) = split b 1 in
    let (pv2,len2) = split rem4 2 in
    match parseCT ct1 with
    | Error(x,y) -> Error(x,y)
    | Correct(ct) ->
    match TLSConstants.parseVersion pv2 with
    | Error(x,y) -> Error(x,y)
    | Correct(pv) ->
    let len = int_of_bytes len2 in
    if len <= 0 || len > max_TLSCipher_fragment_length then
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Wrong frgament length")
    else
        correct(ct,pv,len)

(* This replaces send. It's not called send,
   since it doesn't send anything on the network *)
let recordPacketOut ki conn pv rg ct fragment =
    (* No need to deal with compression. It is handled internally by TLSPlain,
       when returning us the next (already compressed!) fragment *)

    let initEpoch = isInitEpoch ki in
    match (initEpoch, conn) with
    | (true,NullState) ->
        let eh = TLSFragment.emptyHistory ki in
        let payload = TLSFragment.repr ki ct eh rg fragment in
        let packet = makePacket ct pv payload in
        (conn,packet)
    | (false,SomeState(history,state)) ->
        let ad = StatefulPlain.makeAD ki ct in
        let sh = StatefulLHAE.history ki StatefulLHAE.WriterState state in
        let aeadF = StatefulPlain.RecordPlainToStAEPlain ki ct history sh rg fragment in
        let (state,payload) = StatefulLHAE.encrypt ki state ad rg aeadF in
        let history = TLSFragment.extendHistory ki ct history rg fragment in
        let packet = makePacket ct pv payload in
        (SomeState(history,state),packet)
    | _ -> unexpectedError "[recordPacketOut] Incompatible ciphersuite and key type"

let recordPacketIn ki conn headPayload =
    let (header,payload) = split headPayload 5 in
    match parseHeader header with
    | Error(x,y) -> Error(x,y)
    | Correct (parsed) ->
    let (ct,pv,plen) = parsed in
    // tlen is checked in headerLength, which is invoked by Dispatch
    // before invoking this function
    if length payload <> plen then
        let reason = perror __SOURCE_FILE__ __LINE__ "Wrong record packet size" in
        Error(AD_illegal_parameter, reason)
    else
    let initEpoch = isInitEpoch ki in
    match (initEpoch,conn) with
    | (true,NullState) ->
        let rg = (plen,plen) in
        let eh = TLSFragment.emptyHistory ki in
        let msg = TLSFragment.plain ki ct eh rg payload in
        correct(conn,ct,pv,rg,msg)
    | (false,SomeState(history,state)) ->
        let ad = StatefulPlain.makeAD ki ct in
        let decr = StatefulLHAE.decrypt ki state ad payload in
        match decr with
        | Error(x,y) -> Error(x,y)
        | Correct (decrRes) ->
            let (newState, rg, plain) = decrRes in
            let oldH = StatefulLHAE.history ki StatefulLHAE.ReaderState state in
            let msg = StatefulPlain.StAEPlainToRecordPlain ki ct history oldH rg plain in
            let history = TLSFragment.extendHistory ki ct history rg msg in
            let st' = someState ki StatefulLHAE.ReaderState history newState in
            correct(st',ct,pv,rg,msg)
    | _ -> unexpectedError "[recordPacketIn] Incompatible ciphersuite and key type"

let history (e:epoch) (rw:StatefulLHAE.rw) s =
    match s with
    | NullState -> TLSFragment.emptyHistory e
    | SomeState(h,_) -> h
