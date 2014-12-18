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

module TLSInfo

open Bytes
open Date
open TLSConstants

type rw =
    | Reader
    | Writer

type sessionID = bytes
type preRole =
    | Client
    | Server
type Role = preRole

// Client/Server randomness
type random = bytes
type crand = random
type srand = random
type csrands = bytes

type cVerifyData = bytes (* ClientFinished payload *)
type sVerifyData = bytes (* ServerFinished payload *)

type sessionHash = bytes

// Defined here to not depend on TLSExtension
type negotiatedExtension =
    | NE_extended_ms
    | NE_extended_padding

type negotiatedExtensions = list<negotiatedExtension>

type pmsId
val pmsId: PMS.pms -> pmsId
val noPmsId: pmsId

type msId =
  pmsId *
  csrands *
  kefAlg

type SessionInfo = {
    init_crand: crand;
    init_srand: srand;
    protocol_version: ProtocolVersion;
    cipher_suite: cipherSuite;
    compression: Compression;
    extensions: negotiatedExtensions;
    pmsId: pmsId;
    session_hash: sessionHash;
    client_auth: bool;
    clientID: list<Cert.cert>;
    clientSigAlg: Sig.alg;
    serverID: list<Cert.cert>;
    serverSigAlg: Sig.alg;
    sessionID: sessionID;
    }

val csrands: SessionInfo -> bytes
val kefAlg: SessionInfo -> kefAlg
val kefAlg_extended: SessionInfo -> kefAlg
val vdAlg: SessionInfo -> vdAlg
val msi: SessionInfo -> msId

type id = {
  // indexes and algorithms of the session used in the key derivation
  msId   : msId;   // the index of the master secret used for key derivation
  kdfAlg : kdfAlg; // the KDF algorithm used for key derivation
  pv: ProtocolVersion; //Should be part of aeAlg
  aeAlg  : aeAlg;  // the authenticated-encryption algorithms
  csrConn: csrands;
  ext: negotiatedExtensions;
  writer : Role
  }

val macAlg_of_id: id -> macAlg
val encAlg_of_id: id -> encAlg
val pv_of_id: id -> ProtocolVersion

type preEpoch
type epoch = preEpoch

type event =
  | KeyCommit of    csrands * ProtocolVersion * aeAlg * negotiatedExtensions
  | KeyGenClient of csrands * ProtocolVersion * aeAlg * negotiatedExtensions
  | SentCCS of Role * crand * srand * SessionInfo

val id: epoch -> id
val unAuthIdInv: id -> epoch

val isInitEpoch: epoch -> bool
val epochSI: epoch -> SessionInfo
val epochSRand: epoch -> srand
val epochCRand: epoch -> crand
val epochCSRands: epoch -> crand

// Role is of the writer
type preConnectionInfo =
    { role: Role;
      id_rand: random;
      id_in:  epoch;
      id_out: epoch}
type ConnectionInfo = preConnectionInfo
val connectionRole: ConnectionInfo -> Role

val initConnection: Role -> bytes -> ConnectionInfo
val nextEpoch: epoch -> crand -> srand -> SessionInfo -> epoch
//val dual_KeyInfo: epoch -> epoch

val sinfo_to_string: SessionInfo -> string

(* Application configuration options *)

type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type config = {
    minVer: ProtocolVersion;
    maxVer: ProtocolVersion;
    ciphersuites: cipherSuites;
    compressions: list<Compression>;

    (* Handshake specific options *)

    (* Client side *)
    honourHelloReq: helloReqPolicy;
    allowAnonCipherSuite: bool;
    safe_resumption: bool;

    (* Server side *)
    request_client_certificate: bool;
    check_client_version_in_pms_for_old_tls: bool;

    (* Common *)
    safe_renegotiation: bool;
    server_name: Cert.hint;
    client_name: Cert.hint;

    (* Sessions database *)
    sessionDBFileName: string;
    sessionDBExpiry: TimeSpan;

	(* DH groups database *)
	dhDBFileName: string;
	dhDefaultGroupFileName: string;
    dhPQMinLength: nat * nat
    }

val defaultConfig: config

val max_TLSCipher_fragment_length: nat
val fragmentLength: nat

#if ideal
val honestPMS: pmsId -> bool

val safeHS: epoch -> bool
val safeCRE: SessionInfo -> bool
val safeVD: SessionInfo -> bool
val safeHS_SI: SessionInfo -> bool
val auth: epoch -> bool

val safeKDF: id -> bool
val safe: epoch -> bool
val authId: id -> bool
val safeId : id -> bool
#endif
