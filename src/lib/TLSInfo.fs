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

module TLSInfo

open Bytes
open TLSConstants

type sessionID = bytes
type preRole =
    | Client
    | Server
type Role = preRole

// Client/Server randomness
type random = bytes
type crand = random
type srand = random

type pmsData =
    | PMSUnset
    | RSAPMS of RSAKey.pk * ProtocolVersion * bytes
    | DHPMS  of DHGroup.p * DHGroup.g * DHGroup.elt * DHGroup.elt

type SessionInfo = {
    init_crand: crand;
    init_srand: srand;
    protocol_version: ProtocolVersion;
    cipher_suite: cipherSuite;
    compression: Compression;
    pmsData: pmsData;
    client_auth: bool;
    clientID: Cert.cert list;
    serverID: Cert.cert list;
    sessionID: sessionID;
    // Extensions:
    extended_record_padding: bool;
    }

type preEpoch =
    | InitEpoch of Role
    | SuccEpoch of crand * srand * SessionInfo * preEpoch
type epoch = preEpoch
type succEpoch = preEpoch

let isInitEpoch e =
    match e with
    | InitEpoch (_) -> true
    | SuccEpoch (_,_,_,_) -> false

let epochSI e =
    match e with
    | InitEpoch (d) -> Error.unexpectedError "[epochSI] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> si

let epochSRand e =
    match e with
    | InitEpoch (d) -> Error.unexpectedError "[epochSRand] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> sr

let epochCRand e =
    match e with
    | InitEpoch (d) -> Error.unexpectedError "[epochCRand] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> cr

type ConnectionInfo = {
    role: Role; // cached, could be retrieved from id_out
    id_rand: random; // our random
    id_in: epoch;
    id_out: epoch}

let connectionRole ci = ci.role

let initConnection role rand =
    let ctos = InitEpoch Client in
    let stoc = InitEpoch Server in
    match role with
    | Client -> {role = Client; id_rand = rand; id_in = stoc; id_out = ctos}
    | Server -> {role = Server; id_rand = rand; id_in = ctos; id_out = stoc}

let nextEpoch epoch crand srand si =
    SuccEpoch (crand, srand, si, epoch )

// Application configuration
type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type config = {
    minVer: ProtocolVersion
    maxVer: ProtocolVersion
    ciphersuites: cipherSuites
    compressions: Compression list

    (* Handshake specific options *)

    (* Client side *)
    honourHelloReq: helloReqPolicy
    allowAnonCipherSuite: bool

    (* Server side *)
    request_client_certificate: bool
    check_client_version_in_pms_for_old_tls: bool

    (* Common *)
    safe_renegotiation: bool
    server_name: Cert.hint
    client_name: Cert.hint

    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: TimeSpan
    }

let defaultConfig ={
    minVer = SSL_3p0
    maxVer = TLS_1p2
    ciphersuites = cipherSuites_of_nameList
                    [ TLS_RSA_WITH_AES_128_CBC_SHA;
                      TLS_RSA_WITH_3DES_EDE_CBC_SHA ]
    compressions = [ NullCompression ]

    honourHelloReq = HRPResume
    allowAnonCipherSuite = false
    request_client_certificate = false
    check_client_version_in_pms_for_old_tls = true

    safe_renegotiation = true
    server_name = "mitls.example.org"
    client_name = "client.example.org"

    sessionDBFileName = "sessionDBFile.bin"
    sessionDBExpiry = newTimeSpan 1 0 0 0 (*@ one day, as suggested by the RFC *)
    }

let max_TLSPlaintext_fragment_length = 16384 (*@ 2^14 *)
let max_TLSCompressed_fragment_length = max_TLSPlaintext_fragment_length + 1024
let max_TLSCipher_fragment_length = max_TLSCompressed_fragment_length + 1024
let fragmentLength = max_TLSPlaintext_fragment_length

#if ideal
// These functions are used only for specifying ideal implementations
let safe (e:epoch) = failwith "spec only" : bool
let safeHS (e:epoch) = failwith "spec only": bool
let auth (e:epoch) = failwith "spec only": bool
let safeMAC (e:epoch) = failwith "spec only":bool
let safeENC (e:epoch) = failwith "spec only":bool
#endif
