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

module RPC

open Bytes
open TLSInfo
open Error
open Range
open Dispatch
open TLS

let config = {
    TLSInfo.minVer = TLSConstants.SSL_3p0
    TLSInfo.maxVer = TLSConstants.TLS_1p2

    TLSInfo.ciphersuites =
        TLSConstants.cipherSuites_of_nameList [
            TLSConstants.TLS_RSA_WITH_AES_128_CBC_SHA256;
            TLSConstants.TLS_RSA_WITH_AES_128_CBC_SHA;
            TLSConstants.TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        ]

    TLSInfo.compressions = [ TLSConstants.NullCompression ]

    (* Client side *)
    TLSInfo.honourHelloReq = TLSInfo.HRPResume
    TLSInfo.allowAnonCipherSuite = false

    (* Server side *)
    TLSInfo.request_client_certificate = true
    TLSInfo.check_client_version_in_pms_for_old_tls = true

    (* Common *)
    TLSInfo.safe_renegotiation = true
    TLSInfo.server_name = "RPC server"
    TLSInfo.client_name = "RPC client"

    TLSInfo.sessionDBFileName = "sessionDBFile.bin"
    TLSInfo.sessionDBExpiry = Bytes.newTimeSpan 2 0 0 0 (* two days *)
}

let msglen = 128

let padmsg = fun r ->
    if Bytes.length r > msglen then
        fst (Bytes.split r msglen)
    else
        r @| (Bytes.createBytes (msglen - (Bytes.length r)) 0)

let request_bytes  nonce r = nonce @| (padmsg r)
let response_bytes nonce r = nonce @| (padmsg r)

let service = fun r -> r

type DrainResult =
| DRError    of alertDescription option * string
| DRClosed   of Tcp.NetworkStream
| DRContinue of Connection

let rec drainMeta = fun conn ->
  match TLS.read conn with
  | ReadError  (ad,err)          -> DRError (ad,err)
  | Close      s                 -> DRClosed s
  | Fatal      e                 -> DRError (Some(e),"")
  | Warning    (conn, _)         -> DRContinue conn
  | CertQuery  (conn, q, advice) ->
    if advice then
        match authorize conn q with
        |ReadError(ad,err) -> DRError(ad,err)
        | Close(s) -> DRClosed(s)
        | Fatal(e) -> DRError(Some(e),"")
        | Warning(conn,_) -> DRContinue conn
        | Handshaken (conn) -> DRContinue conn
        | DontWrite conn -> drainMeta conn
        | _ -> DRError(None,perror __SOURCE_FILE__ __LINE__ "Internal TLS error")
    else
        refuse conn q; DRError(None,"")
  | Handshaken conn              -> DRContinue conn
  | DontWrite  conn              -> drainMeta conn
  | Read       (conn, _)         ->
        ignore (TLS.full_shutdown conn)
        DRError (None,perror __SOURCE_FILE__ __LINE__ "Internal TLS error")

let rec sendMsg = fun conn rg msg ->
    match TLS.write conn (rg, msg) with
    | WriteError    (ad,err)          -> None
    | WriteComplete conn              -> Some conn
    | WritePartial  (conn, (rg, msg)) -> sendMsg conn rg msg
    | MustRead      conn              ->
        match drainMeta conn with
        | DRError    _    -> None
        | DRClosed   _    -> None
        | DRContinue conn -> sendMsg conn rg msg

let recvMsg = fun conn ->
    let rec doit = fun conn buffer ->
        match TLS.read conn with
          | ReadError  _                 -> None
          | Close      _                 -> None
          | Fatal      _                 -> None
          | Warning    (conn, _)         -> doit conn buffer
          | CertQuery  (conn, q, advice) ->
            if advice then
                match authorize conn q with
                | Warning (conn,_)
                | Handshaken conn
                | DontWrite conn   -> doit conn buffer
                | _ -> None
            else
                refuse conn q; None
          | Handshaken conn              -> doit conn buffer
          | DontWrite  conn              -> doit conn buffer
          | Read       (conn, (r, d))    ->
                let ki     = Dispatch.getEpochIn  conn in
                let s      = TLS.getInStream conn in
                let buffer = buffer @| (DataStream.deltaRepr ki s r d) in

                if Bytes.length buffer < 2+msglen then
                    doit conn buffer
                elif Bytes.length buffer > 2+msglen then
                    ignore (TLS.full_shutdown conn); None
                else
                    Some (conn, buffer)

    in
        doit conn [||]

let doclient (request : string) =
    let ns      = Tcp.connect "127.0.0.1" 5000 in
    let conn    = TLS.connect ns config in

    match drainMeta conn with
    | DRError  _ -> None
    | DRClosed _ -> None

    | DRContinue conn ->
        let nonce   = Nonce.mkRandom 2 in
        let request = request_bytes nonce (Bytes.utf8 request) in

        let msg =
            DataStream.createDelta
                (Dispatch.getEpochOut conn) (TLS.getOutStream conn)
                (Bytes.length request, Bytes.length request) request in

        match sendMsg conn (Bytes.length request, Bytes.length request) msg with
        | Some conn ->
            match recvMsg conn with
            | None -> None
            | Some (conn, response) ->
                ignore (TLS.full_shutdown conn);

                if Bytes.length response <> 2+msglen then
                    None
                else
                    let rnonce, response = Bytes.split response 2 in
                        if Bytes.equalBytes nonce rnonce then
                            Some (Bytes.iutf8 response)
                        else
                            None
        | None -> None

let doserver () =
    let ns = Tcp.listen "127.0.0.1" 5000 in

    let rec doclient = fun () ->
        let client = Tcp.accept ns in

        let result =
            let conn = TLS.accept_connected client config in

            match drainMeta conn with
            | DRError  _ -> false
            | DRClosed _ -> false
            | DRContinue conn ->
                match recvMsg conn with
                | None -> false
                | Some (conn, request) ->
                    if Bytes.length request < 2 then
                        false
                    else
                        let nonce, request = Bytes.split request 2 in
                        let response = service (Bytes.iutf8 request) in
                        let response = response_bytes nonce (Bytes.utf8 response) in

                        let msg =
                            DataStream.createDelta
                                (Dispatch.getEpochOut conn) (TLS.getOutStream conn)
                                (Bytes.length response, Bytes.length response) response in

                        match sendMsg conn (Bytes.length response, Bytes.length response) msg with
                        | Some conn -> ignore (TLS.full_shutdown conn); true
                        | None -> false
        in
            Tcp.close client; result
    in
        doclient ()
