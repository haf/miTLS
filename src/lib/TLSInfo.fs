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
open Date
open TLSConstants
open PMS

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

let noCsr:csrands = Nonce.random 64

type pmsId =
  | NoPmsId
  | SomePmsId of PMS.pms
let pmsId (pms:PMS.pms) = SomePmsId(pms)
let noPmsId = NoPmsId

type pmsData =
  | PMSUnset
  | RSAPMS of RSAKey.pk * ProtocolVersion * bytes
  | DHPMS  of DHGroup.p * DHGroup.g * DHGroup.elt * DHGroup.elt

type msId =
  pmsId *
  csrands *
  creAlg

let noMsId = noPmsId, noCsr, CRE_SSL3_nested

type SessionInfo = {
    init_crand: crand;
    init_srand: srand;
    protocol_version: ProtocolVersion;
    cipher_suite: cipherSuite;
    compression: Compression;
    pmsId: pmsId;
    pmsData: pmsData;
    client_auth: bool;
    clientID: Cert.cert list;
    serverID: Cert.cert list;
    sessionID: sessionID;
    // Extensions:
    extended_record_padding: bool;
    }

let csrands sinfo =
    sinfo.init_crand @| sinfo.init_srand

let prfAlg (si:SessionInfo) =
  si.protocol_version, si.cipher_suite

let creAlg (si:SessionInfo) =
  match si.protocol_version with
  | SSL_3p0           -> CRE_SSL3_nested
  | TLS_1p0 | TLS_1p1 -> let x = CRE_TLS_1p01(extract_label) in x
  | TLS_1p2           -> let ma = prfMacAlg_of_ciphersuite si.cipher_suite
                         CRE_TLS_1p2(extract_label,ma)

let kdfAlg (si:SessionInfo) =
  si.protocol_version, si.cipher_suite

let vdAlg (si:SessionInfo) =
  si.protocol_version, si.cipher_suite

let msi (si:SessionInfo) =
  let csr = csrands si
  let ca = creAlg si
  (si.pmsId, csr, ca)

type preEpoch =
    | InitEpoch of Role
    | SuccEpoch of crand * srand * SessionInfo * preEpoch
type epoch = preEpoch
type succEpoch = preEpoch
type openEpoch = preEpoch

let isInitEpoch e =
    match e with
    | InitEpoch (_) -> true
    | SuccEpoch (_,_,_,_) -> false

let epochSI e =
    match e with
    | InitEpoch (d) -> Error.unexpected "[epochSI] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> si

let epochSRand e =
    match e with
    | InitEpoch (d) -> Error.unexpected "[epochSRand] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> sr

let epochCRand e =
    match e with
    | InitEpoch (d) -> Error.unexpected "[epochCRand] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> cr

let epochCSRands e =
    epochCRand e @| epochSRand e

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

let predEpoch (e:epoch) =
    match e with
    | SuccEpoch(_,_,_, e') -> e'
    | InitEpoch(r) -> failwith "no pred"

let rec epochWriter (e:epoch) =
    match e with
    | InitEpoch(r) -> r
    | SuccEpoch(_,_,_,_) ->
        let pe = predEpoch e in
          epochWriter pe

// the tight index we use as an abstract parameter for StatefulAEAD et al
type id = {
  msId   : msId;
  kdfAlg : kdfAlg;
  pv: ProtocolVersion; //Should be part of aeAlg
  aeAlg  : aeAlg
  csrConn: csrands;
  writer : Role;
  extPad : bool }

//let idInv (i:id):succEpoch = failwith "requires a log, and pointless to implement anyway"

let unAuthIdInv (i:id):epoch =
#if verify
    failwith "only creates epochs for bad ids"
#else
    InitEpoch (i.writer)
#endif

let macAlg_of_id id = macAlg_of_aeAlg id.aeAlg
let encAlg_of_id id = encAlg_of_aeAlg id.aeAlg
let pv_of_id (id:id) =  id.pv
let kdfAlg_of_id (id:id) = id.kdfAlg

type event =
  | KeyCommit of    csrands * ProtocolVersion * aeAlg
  | KeyGenClient of csrands * ProtocolVersion * aeAlg
  | SentCCS of Role * epoch

let noId: id = {
  msId = noMsId;
  kdfAlg=(SSL_3p0,nullCipherSuite);
  pv=SSL_3p0;
  aeAlg= MACOnly(MA_SSLKHASH(NULL));
  csrConn = noCsr;
  writer=Client;
  extPad=false }

let id e =
  if isInitEpoch e
  then noId
  else
    let si     = epochSI e
    let cs     = si.cipher_suite
    let pv     = si.protocol_version
    let msi    = msi si
    let kdfAlg = kdfAlg si
    let aeAlg  = aeAlg cs pv
    let csr    = csrands si
    let wr     = epochWriter e
    let extPad = si.extended_record_padding
    {msId = msi; kdfAlg=kdfAlg; pv=pv; aeAlg = aeAlg; csrConn = csr; writer=wr; extPad = extPad }

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
    extended_padding: bool
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
    extended_padding = false
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

let honestPMS (pi:pmsId) : bool =
    match pi with
    | SomePmsId(PMS.RSAPMS(pk,cv,rsapms))   -> PMS.honestRSAPMS pk cv rsapms
    | SomePmsId(PMS.DHPMS(p,g,gx,gy,dhpms)) -> PMS.honestDHPMS p g gx gy dhpms
    | _ -> false

let strongCRE (ca:creAlg) = failwith "spec only": bool

// These functions are used only for specifying ideal implementations
let safeHS (e:epoch) = failwith "spec only": bool
let safeHS_SI (e:SessionInfo) = failwith "spec only": bool
let safeCRE (e:SessionInfo) = failwith "spec only": bool
let safeVD (e:SessionInfo) = failwith "spec only": bool
let auth (e:epoch) = failwith "spec only": bool
let safe (e:epoch) = failwith "spec only" : bool

let safeKDF (i:id) = failwith "spec only": bool
let authId (i:id) = failwith "spec only":bool
let safeId  (i:id) = failwith "spec only":bool
#endif
