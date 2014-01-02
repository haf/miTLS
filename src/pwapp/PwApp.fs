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

module PwApp

open Bytes
open DER
open Cert
open Dispatch
open TLSInfo
open TLS
open PwToken

// ------------------------------------------------------------------------
type username = string

// ------------------------------------------------------------------------
#if verify
type ca  = ClientAuthenticated   of username * token
type abs = AuthenticatedByServer of SessionInfo  * username
#endif

// ------------------------------------------------------------------------
let config (servname : string) = {
    TLSInfo.minVer = TLSConstants.TLS_1p0
    TLSInfo.maxVer = TLSConstants.TLS_1p0

    TLSInfo.ciphersuites =
        TLSConstants.cipherSuites_of_nameList [
            TLSConstants.TLS_RSA_WITH_AES_128_CBC_SHA;
            TLSConstants.TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        ]

    TLSInfo.compressions = [ TLSConstants.NullCompression ]

    (* Client side *)
    TLSInfo.honourHelloReq = TLSInfo.HRPResume
    TLSInfo.allowAnonCipherSuite = false

    (* Server side *)
    TLSInfo.request_client_certificate = false
    TLSInfo.check_client_version_in_pms_for_old_tls = true

    (* Common *)
    TLSInfo.safe_renegotiation = true
    TLSInfo.server_name = servname
    TLSInfo.client_name = ""

    TLSInfo.sessionDBFileName = "sessionDBFile.bin"
    TLSInfo.sessionDBExpiry = Date.newTimeSpan 1 0 0 0 (* one day *)
}

// ------------------------------------------------------------------------
let read_server_response (c : Connection) (u : username) (tk : token) =
    match TLS.read c with
    | ReadError  (_, _)            -> None
    | Close      _                 -> None
    | Fatal      _                 -> None
    | DontWrite  conn              -> TLS.half_shutdown conn; None
    | Warning    (conn, _)         -> TLS.half_shutdown conn; None
    | CertQuery  (conn, _, _)      -> TLS.half_shutdown conn; None
    | Handshaken conn              -> TLS.half_shutdown conn; None
    | Read       (conn, m)         ->
        let epoch       = TLS.getEpochIn c
        let stream      = TLS.getInStream c
        let (rg, delta) = m

        match PwToken.rp_plain epoch stream rg delta with
        | true  ->
#if verify
            Pi.assume (ClientAuthenticated(u, tk));
#endif
            Some conn
        | false -> TLS.half_shutdown conn; None

let drain (c : Connection) =
    match TLS.read c with
    | ReadError  (_, _)         -> None
    | Close      _              -> None
    | Fatal      _              -> None
    | DontWrite  c              -> Some c
    | Warning    (c, _)         -> TLS.half_shutdown c; None
    | CertQuery  (c, q, _)      ->
        match TLS.authorize c q with
        | ReadError (_,_) -> None
        | Close (_) -> None
        | Fatal (_) -> None
        | DontWrite (c) -> Some c
        | Warning (c,_) -> TLS.half_shutdown c; None
        | CertQuery (c,_,_) -> TLS.half_shutdown c; None
        | Handshaken (c) -> Some c
        | Read (c,_) -> TLS.half_shutdown c; None
    | Handshaken c              -> Some c
    | Read       (c, _)         -> TLS.half_shutdown c; None

let rec do_request (c : Connection) (u : username) (tk : token) =
    let epoch  = TLS.getEpochOut c
    let stream = TLS.getOutStream c
    let rg     = (0, MaxTkReprLen)
    let delta  = PwToken.tk_repr epoch stream u tk

    match TLS.write c (rg, delta) with
    | WriteError    (_, _) -> None
    | WritePartial  (c, _) -> TLS.half_shutdown c; None
    | MustRead      c      -> (match drain c with Some c -> do_request c u tk | None -> None)
    | WriteComplete c      -> read_server_response c u tk

// ------------------------------------------------------------------------
let request (servname : string)  (u : username) (tk : token) =
    let config = config servname
    let s = Tcp.connect "127.0.0.1" 5000
    let c = TLS.connect s config

    do_request c u tk

// ------------------------------------------------------------------------
let rec do_client_response (conn : Connection) (clientok : bool) =
    let epoch  = TLS.getEpochOut conn in
    let stream = TLS.getOutStream conn in
    let rg     = (0, MaxTkReprLen)
    let delta  = PwToken.rp_repr epoch stream clientok in

        match TLS.write conn (rg, delta) with
        | WriteError    (_, _)    -> None
        | WritePartial  (conn, _) -> TLS.half_shutdown conn; None
        | MustRead      conn      -> TLS.half_shutdown conn; None
        | WriteComplete conn      -> Some conn

// ------------------------------------------------------------------------
let rec handle_client_request (conn : Connection) =
    match TLS.read conn with
    | ReadError  (_, s)            -> printfn "%s" s; None
    | Close      _                 -> None
    | Fatal      _                 -> None
    | DontWrite  _                 -> None
    | Warning    (conn, _)         -> handle_client_request conn
    | CertQuery  (conn, q, advice) ->
        if advice then
            match TLS.authorize conn q with
            | ReadError(_,s) -> printf "%s" s; None
            | Close(_) -> None
            | Fatal(_) -> None
            | DontWrite (_) -> None
            | Warning (conn,_) -> handle_client_request conn
            | CertQuery (_,_,_) -> None
            | Handshaken (conn) -> handle_client_request conn
            | Read(conn,m) -> None // should never happen
        else
            refuse conn q; None
    | Handshaken conn              -> handle_client_request conn
    | Read       (conn, m)         ->
        let (r, d) = m in
        let epoch  = TLS.getEpochIn conn in
        let stream = TLS.getInStream conn in

        match PwToken.tk_plain epoch stream r d with
        | None -> TLS.half_shutdown conn; None
        | Some (username, token) ->
            let clientok = PwToken.verify username token

            match do_client_response conn clientok with
            | None      -> None
            | Some conn ->
#if verify
                Pi.assume
                    (AuthenticatedByServer
                        (TLS.getSessionInfo (TLS.getEpochIn conn), username));
#endif
                Some (username, conn)

// ------------------------------------------------------------------------
let response (servname : string) =
    let config = config servname
    let s = Tcp.listen "0.0.0.0" 5000
    let c = TLS.accept s config

    Tcp.stop s;
    handle_client_request c
