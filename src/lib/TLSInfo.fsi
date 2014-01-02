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

type preEpoch
type epoch = preEpoch

val isInitEpoch: epoch -> bool
val epochSI: epoch -> SessionInfo
val epochSRand: epoch -> srand
val epochCRand: epoch -> crand

// Role is of the writer
type ConnectionInfo =
    { role: Role;
      id_rand: random;
      id_in:  epoch;
      id_out: epoch}
val connectionRole: ConnectionInfo -> Role

val initConnection: Role -> bytes -> ConnectionInfo
val nextEpoch: epoch -> crand -> srand -> SessionInfo -> epoch
//val dual_KeyInfo: epoch -> epoch

(* Application configuration options *)

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

val defaultConfig: config

val max_TLSCipher_fragment_length: nat
val fragmentLength: nat

#if ideal
val safe: epoch -> bool
val safeHS: epoch -> bool
val auth: epoch -> bool
val safeMAC: epoch -> bool
val safeENC: epoch -> bool
#endif
