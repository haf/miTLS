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

module Dispatch

open Bytes
open TLSConstants
//open Record
open Tcp
open Error
open Handshake
open Alert
open TLSInfo
open Range

open TLSFragment // Required by F7, or deliver won't parse.

type predispatchState =
  | Init
  | FirstHandshake of TLSConstants.ProtocolVersion
  | Finishing
  | Finished (* Only for Writing side, used to implement TLS False Start *)
  | Open
  | Closing of ProtocolVersion * string
  | Closed

type dispatchState = predispatchState

type dState = {
    disp: dispatchState;
    conn: Record.ConnectionState;
    }

type preGlobalState = {
  (* abstract protocol states for HS/CCS, AL, and AD *)
  handshake: Handshake.hs_state;
  alert    : Alert.state;
  appdata  : AppData.app_state;

  (* connection state for reading and writing *)
  read  : dState;
  write : dState;

  (* The actual socket *)
  ns: NetworkStream;
  }

type globalState = preGlobalState

type Connection = Conn of ConnectionInfo * globalState
let networkStream (Conn(id,g)) = g.ns

type nextCn = Connection
type nullCn = Connection
type query = Cert.chain

type msg_i = (range * DataStream.delta)
type msg_o = (range * DataStream.delta)

// Outcomes for internal, one-message-at-a-time functions
type writeOutcome =
    | WError of string (* internal *)
    | WriteAgain (* Possibly more data to send *)
    | WriteAgainFinishing (* Possibly more data to send, and the outgoing epoch changed *)
    | WAppDataDone (* No more data to send in the current state *)
    | WHSDone
    | WMustRead (* Read until completion of Handshake *)
    | SentFatal of alertDescription * string (* The alert we sent *)
    | SentClose

type readOutcome =
    | WriteOutcome of writeOutcome
    | RError of string (* internal *)
    | RAgain
    | RAppDataDone
    | RQuery of query * bool
    | RHSDone
    | RClose
    | RFatal of alertDescription (* The alert we received *)
    | RWarning of alertDescription (* The alert we received *)

let init ns role poptions =
    let hsInitRes = Handshake.init role poptions in
    let (ci,hs) = hsInitRes in
    let id_in = ci.id_in in
    let id_out = ci.id_out in
    let recv = Record.nullConnState id_in StatefulLHAE.ReaderState in
    let send = Record.nullConnState id_out StatefulLHAE.WriterState in
    let read_state = {disp = Init; conn = recv} in
    let write_state = {disp = Init; conn = send} in
    let al = Alert.init ci in
    let app = AppData.init ci in
    let state = { handshake = hs;
                  alert = al;
                  appdata = app;
                  read = read_state;
                  write = write_state;
                  ns=ns;}
    Conn ( ci, state)

let resume ns sid ops =
    (* Only client side, can never be server side *)
    let (ci,hs) = Handshake.resume sid ops in
    let send = Record.nullConnState ci.id_out StatefulLHAE.WriterState in
    let write_state = {disp = Init; conn = send} in
    let recv = Record.nullConnState ci.id_in  StatefulLHAE.ReaderState in
    let read_state = {disp = Init; conn = recv} in
    let al = Alert.init ci in
    let app = AppData.init ci in
    let res = Conn ( ci,
                     { handshake = hs;
                       alert = al;
                       appdata = app;
                       read = read_state;
                       write = write_state;
                       ns = ns;}) in
    res

let rehandshake (Conn(id,conn)) ops =
    let (accepted,new_hs) = Handshake.rehandshake id conn.handshake ops in // Equivalently, id.id_in.sinfo
    let conn = {conn with handshake = new_hs} in
    (accepted,Conn(id,conn))

let rekey (Conn(id,conn)) ops =
    let (accepted,new_hs) = Handshake.rekey id conn.handshake ops in // Equivalently, id.id_in.sinfo
    let conn = {conn with handshake = new_hs} in
    (accepted,Conn(id,conn))

let request (Conn(id,conn)) ops =
    let (accepted,new_hs) = Handshake.request id conn.handshake ops in // Equivalently, id.id_in.sinfo
    (accepted,Conn(id,{conn with handshake = new_hs}))

let moveToOpenState (Conn(id,c)) =
    let read = c.read in
    match read.disp with
    | Finishing | Finished ->
        let new_read = {read with disp = Open} in
        let c_write = c.write in
        match c_write.disp with
        | Finishing | Finished ->
            let new_write = {c_write with disp = Open} in
            let c = {c with read = new_read; write = new_write} in
            correct c
        | _ -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "")

(* Dispatch dealing with network sockets *)
let pickSendPV (Conn(id,c)) =
    let c_write = c.write
    match c_write.disp with
    | Init -> getMinVersion id c.handshake
    | FirstHandshake(pv) | Closing(pv,_) -> pv
    | Finishing | Finished | Open -> let id_out = id.id_out in let si = epochSI(id_out) in si.protocol_version
    | Closed -> unexpectedError "[pickSendPV] invoked on a Closed connection"

let closeConnection (Conn(id,c)) =
    let new_read = {c.read with disp = Closed} in
    let new_write = {c.write with disp = Closed} in
    let new_hs = Handshake.invalidateSession id c.handshake in
    let c = {c with read = new_read;
                    write = new_write;
                    handshake = new_hs} in
    Conn(id,c)

let abortWithAlert (Conn(id,c)) ad reason =
    let closingPV = pickSendPV (Conn(id,c)) in
    let new_read = {c.read with disp = Closed} in
    let new_write = {c.write with disp = Closing(closingPV,reason)} in
    let new_hs = Handshake.invalidateSession id c.handshake in
    let new_alert = Alert.send_alert id c.alert ad in
    let c = {c with read = new_read;
                    write = new_write;
                    handshake = new_hs;
                    alert = new_alert} in
    (Conn(id,c))

let getReason dstate =
    match dstate with
    | Closing(_,reason) -> reason
    | _ -> ""

let send ns e write pv rg ct frag =
    let res = Record.recordPacketOut e write.conn pv rg ct frag in
    let (conn,data) = res in
    let dState = {write with conn = conn} in
    match Tcp.write ns data with
    | Error(x,y) -> Error(x,y)
    | Correct(_) -> Correct(dState)

(* which fragment should we send next? *)
(* we must send this fragment before restoring the connection invariant *)
let writeOne (Conn(id,c)) (ghr:range) (ghf:AppFragment.fragment) (ghs:DataStream.stream) : writeOutcome * Connection =
  let c_write = c.write in
  match c_write.disp with
  | Closed -> let reason = perror __SOURCE_FILE__ __LINE__ "Trying to write on a closed connection" in (WError(reason), Conn(id,c))
  | _ ->
      let state = c.alert in
      match Alert.next_fragment id state with
      | (Alert.EmptyALFrag,_) ->
          let hs_state = c.handshake in
          let hs_next_res = Handshake.next_fragment id hs_state in
          match hs_next_res with
          | Handshake.OutIdle(_) ->
                // only poll AppData if we're in Open state
                match c_write.disp with
                | Open ->
                    let app_state = c.appdata in
                    match AppData.next_fragment id app_state with
                    | None -> (WAppDataDone,Conn(id,c))
                    | Some (next) ->
                        let (tlen,f,new_app_state) = next in
                        (* we send some data fragment *)
                        let id_out = id.id_out in
                        let c_write_conn = c_write.conn
                        let history = Record.history id_out StatefulLHAE.WriterState c_write_conn in
                        let frag = TLSFragment.AppPlainToRecordPlain id_out history tlen f
                        let pv = pickSendPV (Conn(id,c)) in
                        let resSend = send c.ns id_out c_write pv tlen Application_data frag in
                        match resSend with
                        | Correct(new_write) ->
                            let c = { c with appdata = new_app_state;
                                                write = new_write }
                            (* Fairly, tell we're done, and we won't write more data *)
                            (WAppDataDone, Conn(id,c))

                        | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in (WError(y),closed) (* Unrecoverable error *)
                | _ ->
                    // We are finishing a handshake. Force to read, so that we'll complete the handshake.
                    (WMustRead,Conn(id,c))

          //#begin-alertAttackSend
          | Handshake.OutCCS(rg,ccs,nextID,nextWrite,new_hs_state) ->
                    let nextWCS = Record.initConnState nextID.id_out StatefulLHAE.WriterState nextWrite in
                    (* we send a (complete) CCS fragment *)
                    match c_write.disp with
                    | FirstHandshake(_) | Open ->
                        let history = Record.history id.id_out StatefulLHAE.WriterState c_write.conn in
                        let es = HSFragment.init id.id_out in
                        let hs = TLSFragment.ccsHistory id.id_out history in
                        let ccs = HSFragment.reStream id.id_out es rg ccs hs in
                        let frag = TLSFragment.CCSPlainToRecordPlain id.id_out history rg ccs in
                        let pv = pickSendPV (Conn(id,c)) in
                        let resSend = send c.ns id.id_out c.write pv rg Change_cipher_spec frag in
                        match resSend with
                        | Correct _ -> (* We don't care about next write state, because we're going to reset everything after CCS *)
                            (* Now:
                                - update the index and the state of other protocols
                                - move the outgoing state to Finishing, to signal we must not send appData now. *)
                            let new_write = {c.write with disp = Finishing; conn = nextWCS} in
                            let new_ad = AppData.reset_outgoing id c.appdata nextID in
                            let new_al = Alert.reset_outgoing id c.alert nextID in
                            let c = { c with write = new_write;
                                             handshake = new_hs_state;
                                             alert = new_al;
                                             appdata = new_ad} in
                            (WriteAgainFinishing, Conn(nextID,c))
                        | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in (WError(y),closed) (* Unrecoverable error *)
                    | _ -> (* Internal error: send a fatal alert to the other side *)
                        let reason = perror __SOURCE_FILE__ __LINE__ "Sending CCS in wrong state" in
                        let closing = abortWithAlert (Conn(id,c)) AD_internal_error reason in (WriteAgain, closing)
          //#end-alertAttackSend
          | (Handshake.OutSome(rg,f,new_hs_state)) ->
                      (* we send some handshake fragment *)
                      match c_write.disp with
                      | Init | FirstHandshake(_) | Finishing | Open ->
                          let history = Record.history id.id_out StatefulLHAE.WriterState c_write.conn in
                          let es = HSFragment.init id.id_out in
                          let hs = TLSFragment.handshakeHistory id.id_out history in
                          let f = HSFragment.reStream id.id_out es rg f hs in
                          let frag = TLSFragment.HSPlainToRecordPlain id.id_out history rg f in
                          let pv = pickSendPV (Conn(id,c)) in
                          let resSend = send c.ns id.id_out c.write pv rg Handshake frag in
                          match resSend with
                          | Correct(new_write) ->
                            let c = { c with handshake = new_hs_state;
                                             write  = new_write } in
                            (WriteAgain, Conn(id,c))
                          | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in (WError(y),closed) (* Unrecoverable error *)
                      | _ -> (* Internal error: send a fatal alert to the other side *)
                        let reason = perror __SOURCE_FILE__ __LINE__ "Sending handshake messages in wrong state" in
                        let closing = abortWithAlert (Conn(id,c)) AD_internal_error reason in (WriteAgain, closing)
          | (Handshake.OutFinished(rg,lastFrag,new_hs_state)) ->
                (* check we are in finishing state *)
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    let history = Record.history id.id_out StatefulLHAE.WriterState c_write.conn in
                    let es = HSFragment.init id.id_out in
                    let hs = TLSFragment.handshakeHistory id.id_out history in
                    let lastFrag = HSFragment.reStream id.id_out es rg lastFrag hs in
                    let frag = TLSFragment.HSPlainToRecordPlain id.id_out history rg lastFrag in
                    let pv = pickSendPV (Conn(id,c)) in
                    let resSend = send c.ns id.id_out c.write pv rg Handshake frag in
                    match resSend with
                          | Correct(new_write) ->
                            (* Also move to the Finished state *)
                            let c_write = {new_write with disp = Finished} in
                            let c = { c with handshake = new_hs_state;
                                             write     = c_write }
                            (WMustRead, Conn(id,c))
                          | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in (WError(y),closed) (* Unrecoverable error *)
                | _ -> (* Internal error: send a fatal alert to the other side *)
                        let reason = perror __SOURCE_FILE__ __LINE__ "Sending handshake message in wrong state" in
                        let closing = abortWithAlert (Conn(id,c)) AD_internal_error reason in (WriteAgain, closing)
          | (Handshake.OutComplete(rg,lastFrag,new_hs_state)) ->
                match c_write.disp with
                | Finishing ->
                    (* Send the last fragment *)
                    let history = Record.history id.id_out StatefulLHAE.WriterState c_write.conn in
                    let es = HSFragment.init id.id_out in
                    let hs = TLSFragment.handshakeHistory id.id_out history in
                    let lastFrag = HSFragment.reStream id.id_out es rg lastFrag hs in
                    let frag = TLSFragment.HSPlainToRecordPlain id.id_out history rg lastFrag in
                    let pv = pickSendPV (Conn(id,c)) in
                    let resSend = send c.ns id.id_out c.write pv rg Handshake frag in
                    match resSend with
                    | Correct(new_write) ->
                        let c = { c with handshake = new_hs_state;
                                         write     = new_write }
                        (* Move to the new state *)
                        // Sanity check: in and out session infos should be the same
                        if epochSI(id.id_in) = epochSI(id.id_out) then
                            match moveToOpenState (Conn(id,c)) with
                            | Correct(c) -> (WHSDone,Conn(id,c))
                            | Error(x,y) ->
                                let closing = abortWithAlert (Conn(id,c)) AD_internal_error y in (WriteAgain, closing)
                        else
                            let closed = closeConnection (Conn(id,c)) in
                            let reason = perror __SOURCE_FILE__ __LINE__ "Invalid connection state" in
                            (WError(reason),closed) (* Unrecoverable error *)
                    | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in (WError(y),closed) (* Unrecoverable error *)
                | _ -> (* Internal error: send a fatal alert to the other side *)
                        let reason = perror __SOURCE_FILE__ __LINE__ "Sending handshake message in wrong state" in
                        let closing = abortWithAlert (Conn(id,c)) AD_internal_error reason in (WriteAgain, closing)
      | (Alert.ALFrag(tlen,f),new_al_state) ->
        match c_write.disp with
        | Init | FirstHandshake(_) | Open | Closing(_,_) ->
            let history = Record.history id.id_out StatefulLHAE.WriterState c_write.conn in
            let es = HSFragment.init id.id_out in
            let hs = TLSFragment.alertHistory id.id_out history in
            let f = HSFragment.reStream id.id_out es tlen f hs in
            let frag = TLSFragment.AlertPlainToRecordPlain id.id_out history tlen f in
            let pv = pickSendPV (Conn(id,c)) in
            let c_write = c.write in
            let resSend = send c.ns id.id_out c_write pv tlen Alert frag in
            match resSend with
            | Correct(new_write) ->
                let c = { c with alert   = new_al_state;
                                 write   = new_write }
                (WriteAgain, Conn(id,c ))
            | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in (WError(y),closed) (* Unrecoverable error *)
        | _ ->
            let closed = closeConnection (Conn(id,c)) in
            let reason = perror __SOURCE_FILE__ __LINE__ "Sending alert message in wrong state" in
            (WError(reason),closed) (* Unrecoverable error *)
      | (Alert.LastALFrag(tlen,f,ad),new_al_state) ->
        match c_write.disp with
        | Init | FirstHandshake(_) | Open | Closing(_,_) ->
            (* We're sending a fatal alert. Send it, then close both sending and receiving sides *)
            let history = Record.history id.id_out StatefulLHAE.WriterState c_write.conn in
            let es = HSFragment.init id.id_out in
            let hs = TLSFragment.alertHistory id.id_out history in
            let f = HSFragment.reStream id.id_out es tlen f hs in
            let frag = TLSFragment.AlertPlainToRecordPlain id.id_out history tlen f in
            let pv = pickSendPV (Conn(id,c)) in
            let c_write = c.write in
            let resSend = send c.ns id.id_out c_write pv tlen Alert frag in
            match resSend with
            | Correct(new_write) ->
                let c = {c with alert = new_al_state;
                                write = new_write}
                let closed = closeConnection (Conn(id,c)) in
                let reason = getReason c_write.disp in
                (SentFatal(ad,reason), closed)
            | Error (x,y) -> let closed = closeConnection (Conn(id,c)) in (WError(y),closed) (* Unrecoverable error *)
        | _ ->
            let closed = closeConnection (Conn(id,c)) in
            let reason = perror __SOURCE_FILE__ __LINE__ "Sending alert message in wrong state" in
            (WError(reason),closed) (* Unrecoverable error *)
      | (Alert.LastALCloseFrag(tlen,f),new_al_state) ->
        match c_write.disp with
        | Init | FirstHandshake(_) | Open -> (* Not Closing: this is a graceful closure, should not happen in case of fatal alerts *)
            (* We're sending a close_notify alert. Send it, then only close our sending side.
               If we already received the other close notify, then reading is already closed,
               otherwise we wait to read it, then close. But do not close here. *)
            let history = Record.history id.id_out StatefulLHAE.WriterState c_write.conn in
            let es = HSFragment.init id.id_out in
            let hs = TLSFragment.alertHistory id.id_out history in
            let f = HSFragment.reStream id.id_out es tlen f hs in
            let frag = TLSFragment.AlertPlainToRecordPlain id.id_out history tlen f in
            let pv = pickSendPV (Conn(id,c)) in
            let c_write = c.write in
            let resSend = send c.ns id.id_out c_write pv tlen Alert frag in
            match resSend with
            | Correct(new_write) ->
                let new_write = {new_write with disp = Closed} in
                let c = {c with alert = new_al_state;
                                write = new_write}
                let closed = closeConnection (Conn(id,c)) in
                (SentClose, Conn(id,c))
            | Error (x,y) ->
                let closed = closeConnection (Conn(id,c)) in
                  (WError(y),closed) (* Unrecoverable error *)
        | _ ->
            let closed = closeConnection (Conn(id,c)) in
            let reason = perror __SOURCE_FILE__ __LINE__ "Sending alert message in wrong state" in
            (WError(reason),closed) (* Unrecoverable error *)

let recv (Conn(id,c)) =
    match Tcp.read c.ns 5 with // read & parse the header
    | Error (x,y) -> Error(x,y)
    | Correct header ->
        match Record.headerLength header with
        | Error(x,y) -> Error(x,y)
        | Correct(len) ->
        match Tcp.read c.ns len with // read & process the payload
            | Error (x,y) -> Error(x,y)
            | Correct payload ->
                let c_read = c.read in
                let c_read_conn = c_read.conn in
                let hp = header @| payload in
                let recpkt = Record.recordPacketIn id.id_in c_read_conn hp in
                match recpkt with
                | Error(x,y) -> Error(x,y)
                | Correct(pack) ->
                    let (c_recv,ct,pv,tl,f) = pack in
                    match c.read.disp with
                    | Init -> correct(c_recv,ct,tl,f)
                    | FirstHandshake(expPV) ->
                        if pv = expPV then
                            correct(c_recv,ct,tl,f)
                        else
                            Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Protocol version check failed")
                    | Finishing | Finished | Open ->
                        let si = epochSI(id.id_in) in
                        if pv = si.protocol_version then
                            correct(c_recv,ct,tl,f)
                        else
                            Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Protocol version check failed")
                    | _ -> unexpectedError "[recv] invoked on a closed connection"

let ghostFragment e =
    let s = DataStream.init e in
    let r = (0,0) in
    let d = DataStream.createDelta e s r [||] in
    let f,ns = AppFragment.fragment e s r d in
    r,f,ns

let rec writeAll (Conn(id,s)) =
    let (ghr,ghf,ghs) = ghostFragment id.id_out in
    match writeOne (Conn(id,s)) ghr ghf ghs with
    | (WriteAgain,c) | (WriteAgainFinishing,c) -> writeAll c
    | other -> other

let rec writeAllFinishing conn ghr ghf ghs =
    match writeOne conn ghr ghf ghs with
    | (WError(x),conn) -> (WError(x), conn)
    | (SentFatal(x,y),conn) -> (SentFatal(x,y),conn)
    | (SentClose,conn) -> (SentClose,conn)
    | (WriteAgain,conn) ->
        let (Conn(id,s)) = conn in
        writeAllFinishing (Conn(id,s)) ghr ghf ghs
    | (WMustRead, conn) -> (WMustRead, conn)
    | (_,_) -> unexpectedError "[writeAllFinishing] writeOne returned wrong result"

let rec writeAllTop conn ghr ghf ghs =
    match writeOne conn ghr ghf ghs with
    | (WError(x),conn) -> (WError(x), conn)
    | (SentFatal(x,y),conn) -> (SentFatal(x,y),conn)
    | (SentClose,conn) -> (SentClose,conn)
    | (WAppDataDone,conn) -> (WAppDataDone,conn)
    | (WriteAgainFinishing,conn) ->
        let (Conn(id,s)) = conn in
        writeAllFinishing (Conn(id,s)) ghr ghf ghs
    | (WriteAgain,conn) ->
        let (Conn(id,s)) = conn in
        writeAllTop (Conn(id,s)) ghr ghf ghs
    | (_,_) -> unexpectedError "[writeAllTop] writeOne returned wrong result"

let handleHandshakeOutcome (Conn(id,c)) hsRes =
    let c_read = c.read in
    match hsRes with
    | Handshake.InAck(hs) ->
        let c = { c with handshake = hs} in
        RAgain, Conn(id,c)
    | Handshake.InVersionAgreed(hs,pv) ->
        match c_read.disp with
        | Init ->
            (* Then, also c_write must be in Init state. It means this is the very first, unprotected handshake,
                and we just negotiated the version.
                Set the negotiated version in the current sinfo (read and write side),
                and move to the FirstHandshake state, so that
                protocol version will be properly checked *)
            let new_read = {c_read with disp = FirstHandshake(pv)} in
            let c_write = c.write in
            let new_write = {c_write with disp = FirstHandshake(pv)} in
            let c = {c with handshake = hs;
                            read = new_read;
                            write = new_write} in
                (RAgain, Conn(id,c))
        | _ -> (* It means we are doing a re-negotiation. Don't alter the current version number, because it
                    is perfectly valid. It will be updated after the next CCS, along with all other session parameters *)
            let c = { c with handshake = hs} in
                (RAgain, Conn(id, c))
    | Handshake.InQuery(query,advice,hs) ->
            let c = {c with handshake = hs} in
                (RQuery(query,advice),Conn(id,c))
    | Handshake.InFinished(hs) ->
            (* Ensure we are in Finishing state *)
            match c_read.disp with
                | Finishing ->
                    let c = {c with handshake = hs} in

                    (RAgain,Conn(id,c))
                | _ ->
                    let reason = perror __SOURCE_FILE__ __LINE__ "Finishing handshake in the wrong state" in
                    let closing = abortWithAlert (Conn(id,c)) AD_internal_error reason in
                    let wo,conn = writeAll closing in
                    WriteOutcome(wo),conn
    | Handshake.InComplete(hs) ->
            let c = {c with handshake = hs} in
            (* Ensure we are in Finishing state *)
                match c_read.disp with
                | Finishing ->
                    (* Sanity check: in and out session infos should be the same *)
                    if epochSI(id.id_in) = epochSI(id.id_out) then
                        match moveToOpenState (Conn(id,c)) with
                        | Correct(c) ->
                            (RHSDone, Conn(id,c))
                        | Error(x,y) ->
                            let closing = abortWithAlert (Conn(id,c)) x y in
                            let wo,conn = writeAll closing in
                            WriteOutcome(wo),conn
                    else let closed = closeConnection (Conn(id,c)) in (RError(perror __SOURCE_FILE__ __LINE__ "Invalid connection state"),closed) (* Unrecoverable error *)
                | _ ->
                    let reason = perror __SOURCE_FILE__ __LINE__ "Invalid connection state" in
                    let closing = abortWithAlert (Conn(id,c)) AD_internal_error reason in
                    let wo,conn = writeAll closing in
                    WriteOutcome(wo),conn
    | Handshake.InError(x,y,hs) ->
        let c = {c with handshake = hs} in
        let closing = abortWithAlert (Conn(id,c)) x y in
        let wo,conn = writeAll closing in
        WriteOutcome(wo),conn

(* we have received, decrypted, and verified a record (ct,f); what to do? *)
let readOne (Conn(id,c)) =
  match recv (Conn(id,c)) with
    | Error(x,y) ->
        let closing = abortWithAlert (Conn(id,c)) x y in
        let wo,conn = writeAll closing in
        WriteOutcome(wo),conn
    | Correct(received) ->
        let (c_recv,ct,rg,frag) = received in
        let c_read = c.read in
        let history = Record.history id.id_in StatefulLHAE.ReaderState c_read.conn in
        let c_read = {c_read with conn = c_recv} in
        let c = {c with read = c_read} in
          match c_read.disp with
            | Closed ->
                let reason = perror __SOURCE_FILE__ __LINE__ "Trying to read from a closed connection" in
                let closing = abortWithAlert (Conn(id,c)) AD_internal_error reason in
                let wo,conn = writeAll closing in
                WriteOutcome(wo),conn
            | _ ->
                match (ct,c_read.disp) with
                  | (Handshake, Init) | (Handshake, FirstHandshake(_)) | (Handshake, Finishing) | (Handshake, Open) ->
                      let c_hs = c.handshake in
                        let f = TLSFragment.RecordPlainToHSPlain id.id_in history rg frag in
                        let hsRes = Handshake.recv_fragment id c_hs rg f in
                        handleHandshakeOutcome (Conn(id,c)) hsRes

                  | (Change_cipher_spec, FirstHandshake(_)) | (Change_cipher_spec, Open) ->
                        let f = TLSFragment.RecordPlainToCCSPlain id.id_in history rg frag in
                        match Handshake.recv_ccs id c.handshake rg f with
                          //#begin-alertAttackRecv
                          | InCCSAck(nextID,nextR,hs) ->
                              (* We know statically that Handshake and Application data buffers are empty.
                               * We check Alert. We are going to reset the Alert buffer anyway, so we
                               * never concatenate buffers of different epochs. But it is nicer to abort the
                               * session if some buffers are not in the expected state. *)
                              if Alert.is_incoming_empty id c.alert then
                                  let nextRCS = Record.initConnState nextID.id_in StatefulLHAE.ReaderState nextR in
                                  let new_read = {c_read with disp = Finishing; conn = nextRCS} in
                                  let new_ad = AppData.reset_incoming id c.appdata nextID in
                                  let new_al = Alert.reset_incoming id c.alert nextID in
                                  let c = { c with read = new_read;
                                                   appdata = new_ad;
                                                   alert = new_al;
                                                   handshake = hs;
                                          }
                                  (RAgain, Conn(nextID,c))
                               else
                                  let reason = perror __SOURCE_FILE__ __LINE__ "Changing epoch with non-empty buffers" in
                                  let closing = abortWithAlert (Conn(id,c)) AD_handshake_failure reason in
                                  let wo,conn = writeAll closing in
                                  WriteOutcome(wo),conn
                          //#end-alertAttackRecv
                          | InCCSError (x,y,hs) ->
                              let c = {c with handshake = hs} in
                              let closing = abortWithAlert (Conn(id,c)) x y in
                              let wo,conn = writeAll closing in
                              WriteOutcome(wo),conn

                  | (Alert, Init) | (Alert, FirstHandshake(_)) | (Alert, Open) ->
                        let f = TLSFragment.RecordPlainToAlertPlain id.id_in history rg frag in
                        match Alert.recv_fragment id c.alert rg f with
                          | Correct (Alert.ALAck(state)) ->
                              let c = {c with alert = state} in
                              (RAgain, Conn(id,c))
                          | Correct (Alert.ALClose_notify (state)) ->
                                 (* An outgoing close notify has already been buffered, if necessary *)
                                 (* Only close the reading side of the connection *)
                             let new_read = {c_read with disp = Closed} in
                             let c = { c with read = new_read;
                                              alert = state;
                                     } in
                             (RClose, Conn(id,c))
                          | Correct (Alert.ALFatal (ad,state)) ->
                               (* Other fatal alert, we close both sides of the connection *)
                             let c = {c with alert = state}
                             let closed = closeConnection (Conn(id,c)) in
                             (RFatal(ad), closed)
                          | Correct (Alert.ALWarning (ad,state)) ->
                             (* A warning alert, we carry on. The user will decide what to do *)
                             let c = {c with alert = state}
                             (RWarning(ad), Conn(id,c))
                          | Error (x,y) ->
                              let closing = abortWithAlert (Conn(id,c)) x y in
                              let wo,conn = writeAll closing in
                              WriteOutcome(wo),conn

                  | Application_data, Open ->
                      let f = TLSFragment.RecordPlainToAppPlain id.id_in history rg frag in
                      let appstate = AppData.recv_fragment id c.appdata rg f in
                      let c = {c with appdata = appstate} in
                      (RAppDataDone, Conn(id, c))
                  | _, _ ->
                      let reason = perror __SOURCE_FILE__ __LINE__ "Message type received in wrong state"
                      let closing = abortWithAlert (Conn(id,c)) AD_unexpected_message reason in
                      let wo,conn = writeAll closing in
                      WriteOutcome(wo),conn

let rec read c =
    let orig = c in
    let unitVal = () in
    let (outcome,c) = writeAll c in
    match outcome with
    | WAppDataDone | WMustRead ->
        let (outcome,c) = readOne c in
        match outcome with
        | RAgain | WriteOutcome(WMustRead) | WriteOutcome(WAppDataDone) ->
            read c
        | RAppDataDone ->
            // empty the appData internal buffer, and return its content to the user
            let (Conn(id,conn)) = c in
            match AppData.readAppData id conn.appdata with
            | (Some(b),appState) ->
                let conn = {conn with appdata = appState} in
                let c = Conn(id,conn) in
                c,RAppDataDone,Some(b)
            | (None,_) -> unexpectedError "[read] When RAppDataDone, some data should have been read."
        | RQuery(q,adv) ->
            c,RQuery(q,adv),None
        | RHSDone ->
            c,RHSDone,None
        | RClose ->
            let (Conn(id,conn)) = c in
            match conn.write.disp with
            | Closed ->
                // we already sent a close_notify, tell the user it's over
                c,RClose, None
            | _ ->
                let (outcome,c) = writeAll c in
                match outcome with
                | SentClose ->
                    // clean shoutdown
                    c,RClose,None
                | SentFatal(ad,err) ->
                    c,WriteOutcome(SentFatal(ad,err)),None
                | WError(err) ->
                    c,RError(err),None
                | _ ->
                    c,RError(perror __SOURCE_FILE__ __LINE__ ""),None // internal error
        | RFatal(ad) ->
            c,RFatal(ad),None
        | RWarning(ad) ->
            c,RWarning(ad),None
        | WriteOutcome(wo) -> c,WriteOutcome(wo),None
        | RError(err) -> c,RError(err),None
    | SentClose -> c,WriteOutcome(SentClose),None
    | WHSDone -> c,WriteOutcome(WHSDone),None
    | SentFatal(ad,err) -> c,WriteOutcome(SentFatal(ad,err)),None
    | WError(err) -> c,WriteOutcome(WError(err)),None
    | WriteAgain | WriteAgainFinishing -> unexpectedError "[read] writeAll should never return WriteAgain"

let msgWrite (Conn(id,c)) (rg,d) =
  let (r0,r1) = DataStream.splitRange id.id_out rg in
  if r0 = rg then
    let outStr = AppData.outStream id c.appdata in
    let (f,ns) = AppFragment.fragment id.id_out outStr r0 d
    (rg,f,ns,None)
  else
    let outStr = AppData.outStream id c.appdata in
    let (d0,d1) = DataStream.split id.id_out outStr r0 r1 d in
    let (f,ns) = AppFragment.fragment id.id_out outStr r0 d0 in
    let msg1 = (r1,d1) in
    (r0,f,ns,Some(msg1))

let write (Conn(id,s)) msg =
  let res = msgWrite (Conn(id,s)) msg in
  let (r0,f0,ns,rdOpt) = res in
  let new_appdata = AppData.writeAppData id s.appdata r0 f0 ns in
  let s = {s with appdata = new_appdata} in
  let (outcome,Conn(id,s)) = writeAllTop (Conn(id,s)) r0 f0 ns in
  let new_appdata = AppData.clearOutBuf id s.appdata in
  let s = {s with appdata = new_appdata} in
  Conn(id,s),outcome,rdOpt

let authorize (Conn(id,c)) q =
    let hsRes = Handshake.authorize id c.handshake q in
    let (outcome,c) = handleHandshakeOutcome (Conn(id,c)) hsRes in
    // The following code is borrowed from read.
    // It should be factored out, but this would create a double-recursive function, which we try to avoid.
    match outcome with
    | RAgain ->
        read c
    | RAppDataDone ->
        unexpectedError "[authorize] App data should never be received"
    | RQuery(q,adv) ->
        unexpectedError "[authorize] A query should never be received"
    | RHSDone ->
        c,RHSDone,None
    | RClose ->
        let (Conn(id,conn)) = c in
        match conn.write.disp with
        | Closed ->
            // we already sent a close_notify, tell the user it's over
            c,RClose, None
        | _ ->
            let (outcome,c) = writeAll c in
            match outcome with
            | SentClose ->
                // clean shoutdown
                c,RClose,None
            | SentFatal(ad,err) ->
                c,WriteOutcome(SentFatal(ad,err)),None
            | WError(err) ->
                c,RError(err),None
            | _ ->
                c,RError(perror __SOURCE_FILE__ __LINE__ ""),None // internal error
    | RFatal(ad) ->
        c,RFatal(ad),None
    | RWarning(ad) ->
        c,RWarning(ad),None
    | WriteOutcome(wo) -> c,WriteOutcome(wo),None
    | RError(err) -> c,RError(err),None

let refuse conn (q:query) =
    let reason = perror __SOURCE_FILE__ __LINE__ "Remote certificate could not be verified locally" in
    let conn = abortWithAlert conn AD_unknown_ca reason in
    let _ = writeAll conn in
    ()

let full_shutdown (Conn(id,conn)) =
    let new_al = Alert.send_alert id conn.alert AD_close_notify in
    let conn = {conn with alert = new_al} in
    Conn(id,conn)

let half_shutdown (Conn(id,conn)) =
    let new_al = Alert.send_alert id conn.alert AD_close_notify in
    let conn = {conn with alert = new_al} in
    let _ = writeAll (Conn(id,conn)) in
    ()

let getEpochIn  (Conn(id,state)) = id.id_in
let getEpochOut (Conn(id,state)) = id.id_out
let getInStream  (Conn(id,state)) = AppData.inStream  id state.appdata
let getOutStream (Conn(id,state)) = AppData.outStream id state.appdata
