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

(* Handshake protocol *)
module Handshake

open Bytes
open Error
open TLSConstants
open TLSExtensions
open TLSInfo
open Range

// BEGIN HS_msg

// This section is from the legacy HS_msg module, now merged with Handshake.
// Still, there are some redundancies that should be eliminated,
// by semantically merge the two.

(*** Following RFC5246 A.4 *)

type HandshakeType =
    | HT_hello_request
    | HT_client_hello
    | HT_server_hello
    | HT_certificate
    | HT_server_key_exchange
    | HT_certificate_request
    | HT_server_hello_done
    | HT_certificate_verify
    | HT_client_key_exchange
    | HT_finished

let htBytes t =
    match t with
    | HT_hello_request       -> [|  0uy |]
    | HT_client_hello        -> [|  1uy |]
    | HT_server_hello        -> [|  2uy |]
    | HT_certificate         -> [| 11uy |]
    | HT_server_key_exchange -> [| 12uy |]
    | HT_certificate_request -> [| 13uy |]
    | HT_server_hello_done   -> [| 14uy |]
    | HT_certificate_verify  -> [| 15uy |]
    | HT_client_key_exchange -> [| 16uy |]
    | HT_finished            -> [| 20uy |]

let parseHt (b:bytes) =
    match b with
    | [|  0uy |] -> correct(HT_hello_request      )
    | [|  1uy |] -> correct(HT_client_hello       )
    | [|  2uy |] -> correct(HT_server_hello       )
    | [| 11uy |] -> correct(HT_certificate        )
    | [| 12uy |] -> correct(HT_server_key_exchange)
    | [| 13uy |] -> correct(HT_certificate_request)
    | [| 14uy |] -> correct(HT_server_hello_done  )
    | [| 15uy |] -> correct(HT_certificate_verify )
    | [| 16uy |] -> correct(HT_client_key_exchange)
    | [| 20uy |] -> correct(HT_finished           )
    | _   -> let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_decode_error, reason)

/// Handshake message format

let messageBytes ht data =
    let htb = htBytes ht in
    let vldata = vlbytes 3 data in
    htb @| vldata

let parseMessage buf =
    (* Somewhat inefficient implementation:
       we repeatedly parse the first 4 bytes of the incoming buffer until we have a complete message;
       we then remove that message from the incoming buffer. *)
    if length buf < 4 then Correct(None) (* not enough data to start parsing *)
    else
        let (hstypeb,rem) = Bytes.split buf 1 in
        match parseHt hstypeb with
        | Error(x,y) -> Error(x,y)
        | Correct(hstype) ->
            match vlsplit 3 rem with
            | Error(x,y) -> Correct(None) // not enough payload, try next time
            | Correct(res) ->
                let (payload,rem) = res in
                let to_log = messageBytes hstype payload in
                let res = (rem,hstype,payload,to_log) in
                let res = Some(res) in
                correct(res)

// We implement locally fragmentation, not hiding any length
#if verify
type unsafe = Unsafe of epoch
#endif
let makeFragment ki b =
    let (b0,rem) = if length b < fragmentLength then (b,[||])
                   else Bytes.split b fragmentLength
    let r0 = (length b0, length b0) in
    let f = HSFragment.fragmentPlain ki r0 b0 in
    (r0,f,rem)

// we could use something more general for parsing lists, e.g.
// let rec parseList parseOne b =
//     if length b = 0 then correct([])
//     else
//     match parseOne b with
//     | Correct(x,b) ->
//         match parseList parseOne b with
//         | Correct(xs) -> correct(x::xs)
//         | Error(x,y)  -> Error(x,y)
//     | Error(x,y)      -> Error(x,y)

(** A.4.1 Hello Messages *)

#if verify
type chello = | ClientHelloMsg of (bytes * ProtocolVersion * random * sessionID * cipherSuites * Compression list * bytes)

type preds = ServerLogBeforeClientCertificateVerifyRSA of SessionInfo * bytes
            |ServerLogBeforeClientCertificateVerify of SessionInfo * bytes
            |ServerLogBeforeClientCertificateVerifyDHE of SessionInfo * bytes
            |ServerLogBeforeClientFinished of SessionInfo * bytes
#endif
let parseClientHello data =
    if length data >= 34 then
        let (clVerBytes,cr,data) = split2 data 2 32 in
        match parseVersion clVerBytes with
        | Error(x,y) -> Error(x,y)
        | Correct(cv) ->
        if length data >= 1 then
            match vlsplit 1 data with
            | Error(x,y) -> Error(x,y)
            | Correct (res) ->
            let (sid,data) = res in
            if length sid <= 32 then
                if length data >= 2 then
                    match vlsplit 2 data with
                    | Error(x,y) -> Error(x,y)
                    | Correct (res) ->
                    let (clCiphsuitesBytes,data) = res in
                    match parseCipherSuites clCiphsuitesBytes with
                    | Error(x,y) -> Error(x,y)
                    | Correct (clientCipherSuites) ->
                    if length data >= 1 then
                        match vlsplit 1 data with
                        | Error(x,y) -> Error(x,y)
                        | Correct (res) ->
                        let (cmBytes,extensions) = res in
                        let cm = parseCompressions cmBytes
                        correct(cv,cr,sid,clientCipherSuites,cm,extensions)
                    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
                else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let clientHelloBytes poptions crand session ext =
    let mv = poptions.maxVer in
    let cVerB      = versionBytes mv in
    let random     = crand in
    let csessB     = vlbytes 1 session in
    let cs = poptions.ciphersuites in
    let csb = cipherSuitesBytes cs in
    let ccsuitesB  = vlbytes 2 csb in
    let cm = poptions.compressions in
    let cmb = (compressionMethodsBytes cm) in
    let ccompmethB = vlbytes 1 cmb in
    let data = cVerB @| random @| csessB @| ccsuitesB @| ccompmethB @| ext in
    messageBytes HT_client_hello data

let serverHelloBytes sinfo srand ext =
    let verB = versionBytes sinfo.protocol_version in
    let sidB = vlbytes 1 sinfo.sessionID
    let csB = cipherSuiteBytes sinfo.cipher_suite in
    let cmB = compressionBytes sinfo.compression in
    let data = verB @| srand @| sidB @| csB @| cmB @| ext in
    messageBytes HT_server_hello data

let parseServerHello data =
    if length data >= 34 then
        let (serverVerBytes,serverRandomBytes,data) = split2 data 2 32
        match parseVersion serverVerBytes with
        | Error(x,y) -> Error(x,y)
        | Correct(serverVer) ->
        if length data >= 1 then
            match vlsplit 1 data with
            | Error(x,y) -> Error (x,y)
            | Correct (res) ->
            let (sid,data) = res in
            if length sid <= 32 then
                if length data >= 3 then
                    let (csBytes,cmBytes,data) = split2 data 2 1
                    match parseCipherSuite csBytes with
                    | Error(x,y) -> Error(x,y)
                    | Correct(cs) ->
                    match parseCompression cmBytes with
                    | Error(x,y) -> Error(x,y)
                    | Correct(cm) ->
                    correct(serverVer,serverRandomBytes,sid,cs,cm,data)
                else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let helloRequestBytes = messageBytes HT_hello_request [||]

let CCSBytes = [| 1uy |]

(** A.4.2 Server Authentication and Key Exchange Messages *)

let serverHelloDoneBytes = messageBytes HT_server_hello_done [||]

let serverCertificateBytes cl = messageBytes HT_certificate (Cert.certificateListBytes cl)

let clientCertificateBytes (cs:(Cert.chain * Sig.alg * Sig.skey) option) =

    match cs with
    | None -> messageBytes HT_certificate (Cert.certificateListBytes [])
    | Some(v) ->
        let (certList,_,_) = v in
        messageBytes HT_certificate (Cert.certificateListBytes certList)

let parseClientOrServerCertificate data =
    if length data >= 3 then
        match vlparse 3 data with
        | Error(x,y) -> Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ y)
        | Correct (certList) -> Cert.parseCertificateList certList []
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let sigHashAlgBytesVersion version cs =
     match version with
        | TLS_1p2 ->
            let defaults = default_sigHashAlg version cs in
            let res = sigHashAlgListBytes defaults in
            vlbytes 2 res
        | TLS_1p1 | TLS_1p0 | SSL_3p0 -> [||]

let parseSigHashAlgVersion version data =
    match version with
    | TLS_1p2 ->
        if length data >= 2 then
            match vlsplit 2 data with
            | Error(x,y) -> Error(x,y)
            | Correct (res) ->
            let (sigAlgsBytes,data) = res in
            match parseSigHashAlgList sigAlgsBytes with
            | Error(x,y) -> Error(x,y)
            | Correct (sigAlgsList) -> correct (sigAlgsList,data)
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | TLS_1p1 | TLS_1p0 | SSL_3p0 ->
        correct ([],data)

let certificateRequestBytes sign cs version =
    let certTypes = defaultCertTypes sign cs in
    let ctb = certificateTypeListBytes certTypes in
    let ctb = vlbytes 1 ctb in
    let sigAndAlg = sigHashAlgBytesVersion version cs in
    (* We specify no cert auth *)
    let distNames = distinguishedNameListBytes [] in
    let distNames = vlbytes 2 distNames in
    let data = ctb
            @| sigAndAlg
            @| distNames in
    messageBytes HT_certificate_request data

let parseCertificateRequest version data: (certType list * Sig.alg list * string list) Result =
    if length data >= 1 then
        match vlsplit 1 data with
        | Error(x,y) -> Error(x,y)
        | Correct (res) ->
        let (certTypeListBytes,data) = res in
        match parseCertificateTypeList certTypeListBytes with
        | Error(x,y) -> Error(x,y)
        | Correct(certTypeList) ->
        match parseSigHashAlgVersion version data with
        | Error(x,y) -> Error(x,y)
        | Correct (res) ->
        let (sigAlgs,data) = res in
        if length data >= 2 then
            match vlparse 2 data with
            | Error(x,y) -> Error(x,y)
            | Correct  (distNamesBytes) ->
            let el = [] in
            match parseDistinguishedNameList distNamesBytes el with
            | Error(x,y) -> Error(x,y)
            | Correct (distNamesList) ->
            correct (certTypeList,sigAlgs,distNamesList)

        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(** A.4.3 Client Authentication and Key Exchange Messages *)

let encpmsBytesVersion version encpms =
    match version with
    | SSL_3p0 -> encpms
    | TLS_1p0 | TLS_1p1 | TLS_1p2 -> vlbytes 2 encpms

let parseEncpmsVersion version data =
    match version with
    | SSL_3p0 -> correct (data)
    | TLS_1p0 | TLS_1p1| TLS_1p2 ->
        if length data >= 2 then
            match vlparse 2 data with
            | Correct (encPMS) -> correct(encPMS)
            | Error(x,y) -> Error(x,y)
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let clientKEXBytes_RSA si config =
    if listLength si.serverID = 0 then
        unexpectedError "[clientKEXBytes_RSA] Server certificate should always be present with a RSA signing cipher suite."
    else
        match Cert.get_chain_public_encryption_key si.serverID with
        | Error(x,y) -> Error(x,y)
        | Correct(pubKey) ->
            let pms = CRE.genRSA pubKey config.maxVer in
            let encpms = RSA.encrypt pubKey config.maxVer pms in
            let nencpms = encpmsBytesVersion si.protocol_version encpms in
            let mex = messageBytes HT_client_key_exchange nencpms in
            let pmsdata = RSAPMS(pubKey,config.maxVer,encpms) in
            correct(mex,pmsdata,pms)

let parseClientKEX_RSA si skey cv config data =
    if listLength si.serverID = 0 then
        unexpectedError "[parseClientKEX_RSA] when the ciphersuite can encrypt the PMS, the server certificate should always be set"
    else
        match parseEncpmsVersion si.protocol_version data with
        | Correct(encPMS) ->
            let res = RSA.decrypt skey si cv config.check_client_version_in_pms_for_old_tls encPMS in
            let (Correct(pk)) = Cert.get_chain_public_encryption_key si.serverID in
            correct(RSAPMS(pk,cv,encPMS),res)
        | Error(x,y) -> Error(x,y)

let clientKEXExplicitBytes_DH y =
    let yb = vlbytes 2 y in
    messageBytes HT_client_key_exchange yb

let parseClientKEXExplicit_DH p data =
    if length data >= 2 then
        match vlparse 2 data with
        | Error(x,y) -> Error(x,y)
        | Correct(y) ->
            match DHGroup.checkElement p y with
            | None -> Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid DH key received")
            | Some(y) -> correct y
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

// Unused until we don't support DH ciphersuites.
let clientKEXImplicitBytes_DH = messageBytes HT_client_key_exchange [||]
// Unused until we don't support DH ciphersuites.
let parseClientKEXImplicit_DH data =
    if length data = 0 then
        correct ( () )
    else
        Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(* Digitally signed struct *)

let digitallySignedBytes alg data pv =
    let tag = vlbytes 2 data in
    match pv with
    | TLS_1p2 ->
        let sigHashB = sigHashAlgBytes alg in
        sigHashB @| tag
    | SSL_3p0 | TLS_1p0 | TLS_1p1 -> tag

let parseDigitallySigned expectedAlgs payload pv =
    match pv with
    | TLS_1p2 ->
        if length payload >= 2 then
            let (recvAlgsB,sign) = Bytes.split payload 2 in
            match parseSigHashAlg recvAlgsB with
            | Error(x,y) -> Error(x,y)
            | Correct(recvAlgs) ->
                if sigHashAlg_contains expectedAlgs recvAlgs then
                    if length sign >= 2 then
                        match vlparse 2 sign with
                        | Error(x,y) -> Error(x,y)
                        | Correct(sign) -> correct(recvAlgs,sign)
                    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
                else Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | SSL_3p0 | TLS_1p0 | TLS_1p1 ->
        if listLength expectedAlgs = 1 then
            if length payload >= 2 then
                match vlparse 2 payload with
                | Error(x,y) -> Error(x,y)
                | Correct(sign) ->
                correct(listHead expectedAlgs,sign)
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else unexpectedError "[parseDigitallySigned] invoked with invalid SignatureAndHash algorithms"

(* Server Key exchange *)

let dheParamBytes p g y = (vlbytes 2 p) @| (vlbytes 2 g) @| (vlbytes 2 y)
let parseDHEParams payload =
    if length payload >= 2 then
        match vlsplit 2 payload with
        | Error(x,y) -> Error(x,y)
        | Correct(res) ->
        let (p,payload) = res in
        if length payload >= 2 then
            match vlsplit 2 payload with
            | Error(x,y) -> Error(x,y)
            | Correct(res) ->
            let (g,payload) = res in
            if length payload >= 2 then
                match vlsplit 2 payload with
                | Error(x,y) -> Error(x,y)
                | Correct(res) ->
                let (y,payload) = res in
                // Check g and y are valid elements
                match DHGroup.checkElement p g with
                | None -> Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid DH parameter received")
                | Some(g) ->
                    match DHGroup.checkElement p y with
                    | None -> Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid DH parameter received")
                    | Some(y) -> correct(p,g,y,payload)
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let serverKeyExchangeBytes_DHE dheb alg sign pv =
    let sign = digitallySignedBytes alg sign pv in
    let payload = dheb @| sign in
    messageBytes HT_server_key_exchange payload

let parseServerKeyExchange_DHE pv cs payload =
    match parseDHEParams payload with
    | Error(x,y) -> Error(x,y)
    | Correct(res) ->
        let (p,g,y,payload) = res
        let allowedAlgs = default_sigHashAlg pv cs in
        match parseDigitallySigned allowedAlgs payload pv with
        | Error(x,y) -> Error(x,y)
        | Correct(res) ->
            let (alg,signature) = res
            correct(p,g,y,alg,signature)

let serverKeyExchangeBytes_DH_anon p g y =
    let dehb = dheParamBytes p g y in
    messageBytes HT_server_key_exchange dehb

let parseServerKeyExchange_DH_anon payload =
    match parseDHEParams payload with
    | Error(x,y) -> Error(x,y)
    | Correct(p,g,y,rem) ->
        if equalBytes rem [||] then
            correct(p,g,y)
        else
            Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(* Certificate Verify *)

let makeCertificateVerifyBytes si (ms:PRF.masterSecret) alg skey data =
    // The returned "tag" variable is ghost, only used to avoid
    // existentials in formal verification.
    match si.protocol_version with
    | TLS_1p2 | TLS_1p1 | TLS_1p0 ->
        let tag = Sig.sign alg skey data in
        let payload = digitallySignedBytes alg tag si.protocol_version in
        let mex = messageBytes HT_certificate_verify payload in
        (mex,tag)
#if verify
#else
    | SSL_3p0 ->
        let (sigAlg,_) = alg in
        let alg = (sigAlg,NULL) in
        let toSign = PRF.ssl_certificate_verify si ms sigAlg data in
        let tag = Sig.sign alg skey toSign in
        let payload = digitallySignedBytes alg tag si.protocol_version in
        let mex = messageBytes HT_certificate_verify payload in
        (mex,tag)
#endif

let certificateVerifyCheck si ms algs log payload =
    // The returned byte array is ghost, only used to avoid
    // existentials in formal verification.
    match parseDigitallySigned algs payload si.protocol_version with
    | Correct(res) ->
        let (alg,signature) = res in
        //let (alg,expected) =
        match si.protocol_version with
        | TLS_1p2 | TLS_1p1 | TLS_1p0 ->
            match Cert.get_chain_public_signing_key si.clientID alg with
            | Error(x,y) -> (false,[||])
            | Correct(vkey) ->
                let res = Sig.verify alg vkey log signature in
                (res,signature)
        | SSL_3p0 ->
            let (sigAlg,_) = alg in
            let alg = (sigAlg,NULL) in
            let expected = PRF.ssl_certificate_verify si ms sigAlg log in
            match Cert.get_chain_public_signing_key si.clientID alg with
            | Error(x,y) -> (false,[||])
            | Correct(vkey) ->
                let res = Sig.verify alg vkey expected signature in
                (res,signature)
    | Error(x,y) -> (false,[||])

// State machine begins

type events =
    Authorize of Role * SessionInfo
  | Configure of Role * epoch * config
  | EvSentFinishedFirst of ConnectionInfo * bool
  | SentCCS of Role * epoch
  | Negotiated of Role * SessionInfo * config * config

(* verify data authenticated by the Finished messages *)
type log = bytes         (* message payloads so far, to be eventually authenticated *)
type cVerifyData = bytes (* ClientFinished payload *)
type sVerifyData = bytes (* ServerFinished payload *)

// The constructor indicates either what we are doing locally or which peer message we are expecting,

type serverState =  (* note that the CertRequest bits are determined by the config *)
                    (* we may omit some ProtocolVersion, mostly a ghost variable *)
   | ClientHello                  of cVerifyData * sVerifyData

   | ClientCertificateRSA         of SessionInfo * ProtocolVersion * RSAKey.sk * log
   | ServerCheckingCertificateRSA of SessionInfo * ProtocolVersion * RSAKey.sk * log * Cert.chain * bytes
   | ClientKeyExchangeRSA         of SessionInfo * ProtocolVersion * RSAKey.sk * log

   | ClientCertificateDH          of SessionInfo * log
   | ServerCheckingCertificateDH  of SessionInfo * log * bytes
   | ClientKeyExchangeDH          of SessionInfo * log

   | ClientCertificateDHE         of SessionInfo * DHGroup.p * DHGroup.g * DHGroup.elt * DH.secret * log
   | ServerCheckingCertificateDHE of SessionInfo * DHGroup.p * DHGroup.g * DHGroup.elt * DH.secret * log * Cert.chain * bytes
   | ClientKeyExchangeDHE         of SessionInfo * DHGroup.p * DHGroup.g * DHGroup.elt * DH.secret * log

   | ClientKeyExchangeDH_anon     of SessionInfo * DHGroup.p * DHGroup.g * DHGroup.elt * DH.secret * log

   | CertificateVerify            of SessionInfo * PRF.masterSecret * log
   | ClientCCS                    of SessionInfo * PRF.masterSecret * log
   | ClientFinished               of SessionInfo * PRF.masterSecret * epoch * StatefulLHAE.writer * log
   (* by convention, the parameters are named si, cv, cr', sr', ms, log *)
   | ServerWritingCCS             of SessionInfo * PRF.masterSecret * epoch * StatefulLHAE.writer * cVerifyData * log
   | ServerWritingFinished        of SessionInfo * PRF.masterSecret * epoch * cVerifyData * sVerifyData

   | ServerWritingCCSResume       of epoch * StatefulLHAE.writer * epoch * StatefulLHAE.reader * PRF.masterSecret * log
   | ClientCCSResume              of epoch * StatefulLHAE.reader * sVerifyData * PRF.masterSecret * log
   | ClientFinishedResume         of SessionInfo * PRF.masterSecret * epoch * sVerifyData * log

   | ServerIdle                   of cVerifyData * sVerifyData
   (* the ProtocolVersion is the highest TLS version proposed by the client *)

type clientState =
   | ServerHello                  of crand * sessionID (* * bytes for extensions? *) * cVerifyData * sVerifyData * log

   | ServerCertificateRSA         of SessionInfo * log
   | ClientCheckingCertificateRSA of SessionInfo * log * Cert.cert list * ProtocolVersion option * bytes
   | CertificateRequestRSA        of SessionInfo * log (* In fact, CertReq or SHelloDone will be accepted *)
   | ServerHelloDoneRSA           of SessionInfo * Cert.sign_cert * log

   | ServerCertificateDH          of SessionInfo * log
   | ClientCheckingCertificateDH  of SessionInfo * log * ProtocolVersion option * bytes
   | CertificateRequestDH         of SessionInfo * log (* We pick our cert and store it in sessionInfo as soon as the server requests it.
                                                         We put None if we don't have such a certificate, and we know whether to send
                                                         the Certificate message or not based on the state when we receive the Finished message *)
   | ServerHelloDoneDH            of SessionInfo * log

   | ServerCertificateDHE         of SessionInfo * log
   | ClientCheckingCertificateDHE of SessionInfo * log * ProtocolVersion option * bytes
   | ServerKeyExchangeDHE         of SessionInfo * log
   | CertificateRequestDHE        of SessionInfo * DHGroup.p * DHGroup.g * DHGroup.elt * log
   | ServerHelloDoneDHE           of SessionInfo * Cert.sign_cert * DHGroup.p * DHGroup.g * DHGroup.elt * log

   | ServerKeyExchangeDH_anon of SessionInfo * log (* Not supported yet *)
   | ServerHelloDoneDH_anon of SessionInfo * DHGroup.p * DHGroup.g * DHGroup.elt * log

   | ClientWritingCCS       of SessionInfo * PRF.masterSecret * log
   | ServerCCS              of SessionInfo * PRF.masterSecret * epoch * StatefulLHAE.reader * cVerifyData * log
   | ServerFinished         of SessionInfo * PRF.masterSecret * epoch * cVerifyData * log

   | ServerCCSResume        of epoch * StatefulLHAE.writer * epoch * StatefulLHAE.reader * PRF.masterSecret * log
   | ServerFinishedResume   of epoch * StatefulLHAE.writer * PRF.masterSecret * log
   | ClientWritingCCSResume of epoch * StatefulLHAE.writer * PRF.masterSecret * sVerifyData * log
   | ClientWritingFinishedResume of cVerifyData * sVerifyData

   | ClientIdle             of cVerifyData * sVerifyData

type protoState = // Cannot use Client and Server, otherwise clashes with Role
  | PSClient of clientState
  | PSServer of serverState

let clientState (ci:ConnectionInfo) (p:clientState) = PSClient(p)
let serverState (ci:ConnectionInfo) (p:serverState) = PSServer(p)

type hs_state = {
  (* I/O buffers *)
  hs_outgoing    : bytes;                  (* outgoing data *)
  hs_incoming    : bytes;                  (* partial incoming HS message *)
  (* local configuration *)
  poptions: config;
  sDB: SessionDB.SessionDB;
  (* current handshake & session we are establishing *)
  pstate: protoState;
}

type nextState = hs_state

/// Initiating Handshakes, mostly on the client side.

let init (role:Role) poptions =
    (* Start a new session without resumption, as the first epoch on this connection. *)
    let sid = [||] in
    let rand = Nonce.mkHelloRandom() in
    match role with
    | Client ->
        let ci = initConnection role rand in
        Pi.assume (Configure(Client,ci.id_in,poptions));
        let ext = extensionsBytes poptions.safe_renegotiation [||] in
        let cHelloBytes = clientHelloBytes poptions rand sid ext in
        let sdb = SessionDB.create poptions in
        (ci,{hs_outgoing = cHelloBytes;
                     hs_incoming = [||];
                     poptions = poptions;
                     sDB = sdb;
                     pstate = PSClient (ServerHello (rand, sid, [||], [||], cHelloBytes))
            })
    | Server ->
        let ci = initConnection role rand in
        Pi.assume (Configure(Client,ci.id_in,poptions));
        let sdb = SessionDB.create poptions in
        (ci,{hs_outgoing = [||]
             hs_incoming = [||]
             poptions = poptions
             sDB = sdb
             pstate = PSServer (ClientHello([||],[||]))
            })

let resume next_sid poptions =
    (* Resume a session, as the first epoch on this connection.
       Set up our state as a client. Servers cannot resume *)

    (* Search a client sid in the DB *)
    let sDB = SessionDB.create poptions in
    match SessionDB.select sDB (next_sid,Client,poptions.server_name) with
    | None -> init Client poptions
    | Some (retrieved) ->
    let (retrievedSinfo,retrievedMS) = retrieved in
    match retrievedSinfo.sessionID with
    | [||] -> unexpectedError "[resume] a resumed session should always have a valid sessionID"
    | sid ->
    let rand = Nonce.mkHelloRandom () in
    let ci = initConnection Client rand in
    Pi.assume (Configure(Server,ci.id_in,poptions));
    let ext = extensionsBytes poptions.safe_renegotiation [||]
    let cHelloBytes = clientHelloBytes poptions rand sid ext in
    let sdb = SessionDB.create poptions
    (ci,{hs_outgoing = cHelloBytes
         hs_incoming = [||]
         poptions = poptions
         sDB = sdb
         pstate = PSClient (ServerHello (rand, sid, [||], [||], cHelloBytes))
        })

let rehandshake (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    (* Start a non-resuming handshake, over an existing epoch.
       Only client side, since a server can only issue a HelloRequest *)
    match state.pstate with
    | PSClient (cstate) ->
        match cstate with
        | ClientIdle(cvd,svd) ->
            let rand = Nonce.mkHelloRandom () in
            let sid = [||] in
            let ext = extensionsBytes ops.safe_renegotiation cvd in
            let cHelloBytes = clientHelloBytes ops rand sid ext in
            Pi.assume (Configure(Client,ci.id_in,ops));
            let sdb = SessionDB.create ops
            (true,{hs_outgoing = cHelloBytes
                   hs_incoming = [||]
                   poptions = ops
                   sDB = sdb
                   pstate = PSClient (ServerHello (rand, sid, cvd,svd, cHelloBytes))
                   })
        | _ -> (* handshake already happening, ignore this request *)
            (false,state)
    | PSServer (_) -> unexpectedError "[rehandshake] should only be invoked on client side connections."

let rekey (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    if isInitEpoch(ci.id_out) then
        unexpectedError "[rekey] should only be invoked on established connections."
    else
    (* Start a (possibly) resuming handshake over an existing epoch *)
    let si = epochSI(ci.id_out) in // or equivalently ci.id_in
    let sidOp = si.sessionID in
    match sidOp with
    | [||] -> (* Non resumable session, let's do a full handshake *)
        rehandshake ci state ops
    | sid ->
        let sDB = SessionDB.create ops in
        (* Ensure the sid is in the SessionDB *)
        match SessionDB.select sDB (sid,Client,ops.server_name) with
        | None -> (* Maybe session expired, or was never stored. Let's not resume *)
            rehandshake ci state ops
        | Some s ->
            let (retrievedSinfo,retrievedMS) = s
            match state.pstate with
            | PSClient (cstate) ->
                match cstate with
                | ClientIdle(cvd,svd) ->
                    let rand = Nonce.mkHelloRandom () in
                    let ext = extensionsBytes ops.safe_renegotiation cvd in
                    Pi.assume (Configure(Client,ci.id_in,ops));
                    let cHelloBytes = clientHelloBytes ops rand sid ext in
                    (true,{hs_outgoing = cHelloBytes
                           hs_incoming = [||]
                           poptions = ops
                           sDB = sDB
                           pstate = PSClient (ServerHello (rand, sid, cvd, svd, cHelloBytes))
                           })
                | _ -> (* Handshake already ongoing, ignore this request *)
                    (false,state)
            | PSServer (_) -> unexpectedError "[rekey] should only be invoked on client side connections."

let request (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    match state.pstate with
    | PSClient _ -> unexpectedError "[request] should only be invoked on server side connections."
    | PSServer (sstate) ->
        match sstate with
        | ServerIdle(cvd,svd) ->
            let sdb = SessionDB.create ops
            (* Put HelloRequest in outgoing buffer (and do not log it), and move to the ClientHello state (so that we don't send HelloRequest again) *)
            (true, { hs_outgoing = helloRequestBytes
                     hs_incoming = [||]
                     poptions = ops
                     sDB = sdb
                     pstate = PSServer(ClientHello(cvd,svd))
                    })
        | _ -> (* Handshake already ongoing, ignore this request *)
            (false,state)

let getPrincipal ci state =
  match ci.role with
    | Client -> state.poptions.server_name
    | Server -> state.poptions.client_name

let invalidateSession ci state =
    if isInitEpoch(ci.id_in) then
        state
    else
        let si = epochSI(ci.id_in)
        match si.sessionID with
        | [||] -> state
        | sid ->
            let hint = getPrincipal ci state
            let sdb = SessionDB.remove state.sDB (sid,ci.role,hint) in
            {state with sDB=sdb}

let getNextEpochs ci si crand srand =
    let id_in  = nextEpoch ci.id_in  crand srand si in
    let id_out = nextEpoch ci.id_out crand srand si in
    {ci with id_in = id_in; id_out = id_out}

type outgoing =
  | OutIdle of nextState
  | OutSome of range * HSFragment.plain * nextState
  | OutCCS of  range * HSFragment.plain (* the unique one-byte CCS *) *
               ConnectionInfo * StatefulLHAE.state * nextState
  | OutFinished of range * HSFragment.plain * nextState
  | OutComplete of range * HSFragment.plain * nextState

let check_negotiation (r:Role) (si:SessionInfo) (c:config) =
  Pi.assume (Negotiated(r,si,c,c))

let next_fragment ci state =
    match state.hs_outgoing with
    | [||] ->
        match state.pstate with
        | PSClient(cstate) ->
            match cstate with
            | ClientWritingCCS (si,ms,log) ->
                let next_ci = getNextEpochs ci si si.init_crand si.init_srand in
                let (writer,reader) = PRF.keyGen next_ci ms in
                Pi.assume (SentCCS(Client,next_ci.id_out));
                let cvd = PRF.makeVerifyData next_ci.id_out Client ms log in
                let cFinished = messageBytes HT_finished cvd in
                let log = log @| cFinished in
                let (rg,f,_) = makeFragment ci.id_out CCSBytes in
                let ci = {ci with id_out = next_ci.id_out} in

                OutCCS(rg,f,ci,writer,
                       {state with hs_outgoing = cFinished
                                   pstate = PSClient(ServerCCS(si,ms,next_ci.id_in,reader,cvd,log))})

            | ClientWritingCCSResume(e,w,ms,svd,log) ->
                Pi.assume (SentCCS(Client,e));
                let cvd = PRF.makeVerifyData e Client ms log in
                let cFinished = messageBytes HT_finished cvd in
                let (rg,f,_) = makeFragment ci.id_out CCSBytes in
                let ci = {ci with id_out = e} in

                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = cFinished
                                   pstate = PSClient(ClientWritingFinishedResume(cvd,svd))})

            | _ -> OutIdle(state)
        | PSServer(sstate) ->
            match sstate with
            | ServerWritingCCS (si,ms,e,w,cvd,log) ->
                Pi.assume (SentCCS(Server,e));
                let svd = PRF.makeVerifyData e Server ms log in
                let sFinished = messageBytes HT_finished svd in
                let (rg,f,_) = makeFragment ci.id_out CCSBytes in
                let ci = {ci with id_out = e} in

                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = sFinished
                                   pstate = PSServer(ServerWritingFinished(si,ms,e,cvd,svd))})

            | ServerWritingCCSResume(we,w,re,r,ms,log) ->
                Pi.assume (SentCCS(Server,we));
                let svd = PRF.makeVerifyData we Server ms log in
                let sFinished = messageBytes HT_finished svd in
                let log = log @| sFinished in
                let (rg,f,_) = makeFragment ci.id_out CCSBytes in
                let ci = {ci with id_out = we} in

                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = sFinished
                                   pstate = PSServer(ClientCCSResume(re,r,svd,ms,log))})

            | _ -> OutIdle(state)
    | outBuf ->
        let (rg,f,remBuf) = makeFragment ci.id_out outBuf in
        match remBuf with
        | [||] ->
            match state.pstate with
            | PSClient(cstate) ->
                match cstate with
                | ServerCCS (_,_,_,_,_,_) ->
#if verify
                    Pi.assume(EvSentFinishedFirst(ci,true));
#endif
                    OutFinished(rg,f,{state with hs_outgoing = remBuf})
                | ClientWritingFinishedResume(cvd,svd) ->
                    check_negotiation Client (epochSI ci.id_out) state.poptions;
                    OutComplete(rg,f,
                                {state with hs_outgoing = remBuf
                                            pstate = PSClient(ClientIdle(cvd,svd))})

                | _ -> OutSome(rg,f,{state with hs_outgoing = remBuf})
            | PSServer(sstate) ->
                match sstate with
                | ServerWritingFinished(si,ms,e,cvd,svd) ->
                    if equalBytes si.sessionID [||] then
                      check_negotiation Server si state.poptions;
                      OutComplete(rg,f,
                                  {state with hs_outgoing = remBuf
                                              pstate = PSServer(ServerIdle(cvd,svd))})

                    else
                      let sdb = SessionDB.insert state.sDB (si.sessionID,Server,state.poptions.client_name) (si,ms)
                      check_negotiation Server si state.poptions;
                      OutComplete(rg,f,
                                  {state with hs_outgoing = remBuf
                                              pstate = PSServer(ServerIdle(cvd,svd))
                                              sDB = sdb})

                | ClientCCSResume(_,_,_,_,_) ->
#if verify
                    Pi.assume(EvSentFinishedFirst(ci,true));
#endif
                    OutFinished(rg,f,{state with hs_outgoing = remBuf})
                | _ -> OutSome(rg,f,{state with hs_outgoing = remBuf})
        | _ -> OutSome(rg,f,{state with hs_outgoing = remBuf})

type incoming = (* the fragment is accepted, and... *)
  | InAck of hs_state
  | InVersionAgreed of hs_state * ProtocolVersion
  | InQuery of Cert.chain * bool * hs_state
  | InFinished of hs_state
  | InComplete of hs_state
  | InError of alertDescription * string * hs_state

type incomingCCS =
  | InCCSAck of ConnectionInfo * StatefulLHAE.state * hs_state
  | InCCSError of alertDescription * string * hs_state

/// ClientKeyExchange
let find_client_cert_sign certType certAlg (distName:string list) pv hint =
    match pv with
    | TLS_1p2 ->
        let keyAlg = sigHashAlg_bySigList certAlg (cert_type_list_to_SigAlg certType) in
        Cert.for_signing certAlg hint keyAlg
    | TLS_1p1 | TLS_1p0 | SSL_3p0 ->
        let certAlg = cert_type_list_to_SigHashAlg certType pv
        let keyAlg = sigHashAlg_bySigList certAlg (cert_type_list_to_SigAlg certType) in
        Cert.for_signing certAlg hint keyAlg

let getCertificateBytes (si:SessionInfo) (cert_req:(Cert.chain * Sig.alg * Sig.skey) option) =
  let clientCertBytes = clientCertificateBytes cert_req in
  match cert_req with
    | None when si.client_auth = true -> clientCertBytes,[]
    | Some x when si.client_auth = true ->
        let (certList,_,_) = x in clientCertBytes,certList
    | _ when si.client_auth = false -> [||],[]

let getCertificateVerifyBytes (si:SessionInfo) (ms:PRF.masterSecret) (cert_req:(Cert.chain * Sig.alg * Sig.skey) option) (l:log) =
  match cert_req with
    | None when si.client_auth = true ->
        (* We sent an empty Certificate message, so no certificate verify message at all *)
        [||]
    | Some(x) when si.client_auth = true ->
        let (certList,algs,skey) = x in
          let (mex,_) = makeCertificateVerifyBytes si ms algs skey l in
          mex
    | _ when si.client_auth = false ->
        (* No client certificate ==> no certificateVerify message *)
        [||]

let prepare_client_output_full_RSA (ci:ConnectionInfo) (state:hs_state) (si:SessionInfo) (cert_req:Cert.sign_cert) (log:log) : (hs_state * SessionInfo * PRF.masterSecret * log) Result =
    let clientCertBytes,certList = getCertificateBytes si cert_req in
    let si = {si with clientID = certList}
    let log = log @| clientCertBytes in

    match clientKEXBytes_RSA si state.poptions with
    | Error(x,y) -> Error(x,y)
    | Correct(v) ->
    let (clientKEXBytes,pmsdata,pms)  = v in

    let si = {si with pmsData = pmsdata} in

    let log = log @| clientKEXBytes in
    let pop = state.poptions in
    let ms = CRE.prfSmoothRSA si pop.maxVer pms in

    let certificateVerifyBytes = getCertificateVerifyBytes si ms cert_req log in

    let log = log @| certificateVerifyBytes in

    (* Enqueue current messages in output buffer *)
    let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
    let new_outgoing = state.hs_outgoing @| to_send in
    correct ({state with hs_outgoing = new_outgoing},si,ms,log)

let sessionInfoCertBytesAuth (si:SessionInfo) (cert_req:Cert.sign_cert)=
  if si.client_auth then
    let cb = clientCertificateBytes cert_req in
    match cert_req with
     | None -> (si,cb)
     | Some(x) ->
         let (certList,_,_) = x in
         ({si with clientID = certList},cb)
  else (si,[||])

let certificateVerifyBytesAuth (si:SessionInfo) (ms:PRF.masterSecret) (cert_req:Cert.sign_cert) (log:bytes) =
        if si.client_auth then
            match cert_req with
            | None ->
                (* We sent an empty Certificate message, so no certificate verify message at all *)
                [||]
            | Some(x) ->
                let (certList,algs,skey) = x in
                let (mex,_) = makeCertificateVerifyBytes si ms algs skey log in
                mex
        else
            (* No client certificate ==> no certificateVerify message *)
            [||]

let prepare_client_output_full_DHE (ci:ConnectionInfo) (state:hs_state) (si:SessionInfo) (cert_req:Cert.sign_cert) (p:DHGroup.p) (g:DHGroup.g) (sy:DHGroup.elt) (log:log) : (hs_state * SessionInfo * PRF.masterSecret * log) Result =

    (* pre: Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> DHE.PP((p,g)) /\ ServerDHE((p,g),sy,si.init_crand @| si.init_srand) *)
    (* moreover, by definition ServerDHE((p,g),sy,si.init_crand @| si.init_srand) implies ?sx.DHE.Exp((p,g),sx,sy) *)

    let (si,clientCertBytes) = sessionInfoCertBytesAuth si cert_req in

    let log = log @| clientCertBytes

    let (cy,x) = DH.genKey p g in
    (* post: DHE.Exp((p,g),x,cy) *)

    let si = {si with pmsData = DHPMS(p,g,cy,sy)} in
    (* si is now constant *)

    let clientKEXBytes = clientKEXExplicitBytes_DH cy in
    let log = log @| clientKEXBytes in

    let pms = DH.exp p g cy sy x in
    (* the post of this call is !sx,cy. PP((p,g) /\ DHE.Exp((p,g),x,cy)) /\ DHE.Exp((p,g),sx,sy) -> DHE.Secret((p,g),cy,sy) *)
    (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> DHE.Secret((p,g),cy,sy) *)
    let ms = CRE.prfSmoothDHE si p g cy sy pms in
    (* the post of this call is !p,g,gx,gy. StrongHS(si) /\ DHE.Secret((p,g),gx,gy) -> PRFs.Secret(ms) *)
    (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> PRFs.Secret(ms) *)

    let certificateVerifyBytes = certificateVerifyBytesAuth si ms cert_req log in

    let log = log @| certificateVerifyBytes in

    let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
    let new_outgoing = state.hs_outgoing @| to_send in
    correct ({state with hs_outgoing = new_outgoing},si,ms,log)
(* #endif *)

let on_serverHello_full (ci:ConnectionInfo) crand log to_log (shello:ProtocolVersion * srand * sessionID * cipherSuite * Compression * bytes) =
    let log = log @| to_log in
    let (sh_server_version,sh_random,sh_session_id,sh_cipher_suite,sh_compression_method,sh_neg_extensions) = shello
    let si = { clientID = []
               client_auth = false
               serverID = []
               sessionID = sh_session_id
               protocol_version = sh_server_version
               cipher_suite = sh_cipher_suite
               compression = sh_compression_method
               init_crand = crand
               init_srand = sh_random
               pmsData = PMSUnset
               extended_record_padding = false
               } in
    (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
    if isAnonCipherSuite sh_cipher_suite then
        PSClient(ServerKeyExchangeDH_anon(si,log))
    elif isDHCipherSuite sh_cipher_suite then
        PSClient(ServerCertificateDH(si,log))
    elif isDHECipherSuite sh_cipher_suite then
        PSClient(ServerCertificateDHE(si,log))
    elif isRSACipherSuite sh_cipher_suite then
        PSClient(ServerCertificateRSA(si,log))
    else
        unexpectedError "[on_serverHello_full] Unknown ciphersuite"

let parseMessageState (ci:ConnectionInfo) state =
    match parseMessage state.hs_incoming with
    | Error(x,y) -> Error(x,y)
    | Correct(res) ->
        match res with
        | None -> correct(None)
        | Some(x) ->
             let (rem,hstype,payload,to_log) = x in
             let state = { state with hs_incoming = rem } in
             let nx = (state,hstype,payload,to_log) in
             let res = Some(nx) in
             correct(res)

let rec recv_fragment_client (ci:ConnectionInfo) (state:hs_state) (agreedVersion:ProtocolVersion option) =
    match parseMessageState ci state with
    | Error(x,y) -> InError(x,y,state)
    | Correct(res) ->
      match res with
      | None ->
          match agreedVersion with
          | None      -> InAck(state)
          | Some (pv) -> InVersionAgreed(state,pv)
      | Some (res) ->
      let (state,hstype,payload,to_log) = res in
      match state.pstate with
      | PSClient(cState) ->
        match hstype with
        | HT_hello_request ->
            match cState with
            | ClientIdle(_,_) ->
                (* This is a legitimate hello request.
                   Handle it, but according to the spec do not log this message *)
                match state.poptions.honourHelloReq with
                | HRPIgnore -> recv_fragment_client ci state agreedVersion
                | HRPResume -> let (_,state) = rekey ci state state.poptions in InAck(state)       (* Terminating case, we're not idle anymore *)
                | HRPFull   -> let (_,state) = rehandshake ci state state.poptions in InAck(state) (* Terminating case, we're not idle anymore *)
            | _ ->
                (* RFC 7.4.1.1: ignore this message *)
                recv_fragment_client ci state agreedVersion

        | HT_server_hello ->
            match cState with
            | ServerHello (crand,sid,cvd,svd,log) ->
                match parseServerHello payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct (shello) ->
                  let (sh_server_version,sh_random,sh_session_id,sh_cipher_suite,sh_compression_method,sh_neg_extensions) = shello
                  let pop = state.poptions
                  // Sanity checks on the received message; they are security relevant.
                  // Check that the server agreed version is between maxVer and minVer.
                  if  (geqPV sh_server_version pop.minVer
                       && geqPV pop.maxVer sh_server_version) = false
                  then

                    InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation",state)

                  else
                  // Check that the negotiated ciphersuite is in the proposed list.
                  // Note: if resuming a session, we still have to check that this ciphersuite is the expected one!
                  if  (Bytes.memr state.poptions.ciphersuites sh_cipher_suite) = false
                  then

                    InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation",state)

                  else
                  // Check that the compression method is in the proposed list.
                  if (Bytes.memr state.poptions.compressions sh_compression_method) = false
                  then

                    InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation",state)

                  else
                  // Parse extensions
                  match parseExtensions sh_neg_extensions with
                  | Error(x,y) ->

                      InError(x,y,state)

                  | Correct(extList) ->
                  // Handling of safe renegotiation //#begin-safe_renego
                  let safe_reneg_result =
                    if state.poptions.safe_renegotiation then
                        let expected = cvd @| svd in
                        inspect_ServerHello_extensions extList expected
                        //#end-safe_renego
                    else
                        // RFC Sec 7.4.1.4: with no safe renegotiation, we never send extensions; if the server sent any extension
                        // we MUST abort the handshake with unsupported_extension fatal alter (handled by the dispatcher)
                        if (equalBytes sh_neg_extensions [||]) = false
                        then Error(AD_unsupported_extension, perror __SOURCE_FILE__ __LINE__ "The server gave an unknown extension")
                        else let unitVal = () in correct (unitVal)
                  match safe_reneg_result with
                    | Error (x,y) ->

                        InError (x,y,state)

                    | Correct _ ->
                        // Log the received message.
                        (* Check whether we asked for resumption *)
                        if equalBytes sid [||] then
                            (* we did not request resumption, do a full handshake *)
                            (* define the sinfo we're going to establish *)
                            let next_pstate = on_serverHello_full ci crand log to_log shello in

                            recv_fragment_client ci {state with pstate = next_pstate}  (Some sh_server_version)

                        else
                            if equalBytes sid sh_session_id then (* use resumption *)
                                (* Search for the session in our DB *)
                                match SessionDB.select state.sDB (sid,Client,state.poptions.server_name) with
                                | None ->
                                    (* This can happen, although we checked for the session before starting the HS.
                                       For example, the session may have expired between us sending client hello, and now. *)

                                    InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "A session expried while it was being resumed",state)

                                | Some(storable) ->
                                let (si,ms) = storable in
                                let log = log @| to_log in
                                (* Check that protocol version, ciphersuite and compression method are indeed the correct ones *)
                                if si.protocol_version = sh_server_version then
                                    if si.cipher_suite = sh_cipher_suite then
                                        if si.compression = sh_compression_method then
                                            let next_ci = getNextEpochs ci si crand sh_random in
                                            let (writer,reader) = PRF.keyGen next_ci ms in
                                            let nout = next_ci.id_out in
                                            let nin = next_ci.id_in in
                                            recv_fragment_client ci
                                              {state with pstate = PSClient(ServerCCSResume(nout,writer,
                                                                                            nin,reader,
                                                                                            ms,log))}
                                              (Some(sh_server_version))
                                        else

                                          InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation",state)

                                    else

                                      InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation",state)

                                else

                                  InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation",state)

                            else (* server did not agree on resumption, do a full handshake *)
                                (* define the sinfo we're going to establish *)
                                let next_pstate = on_serverHello_full ci crand log to_log shello in
                                recv_fragment_client ci {state with pstate = next_pstate} (Some(sh_server_version))
            | _ ->

                InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerHello arrived in the wrong state",state)

        | HT_certificate ->
            match cState with
            // Most of the code in the branches is duplicated, but it helps for verification
            | ServerCertificateRSA (si,log) ->
                match parseClientOrServerCertificate payload with
                | Error(x,y) ->

                    InError(x,y,state)

                | Correct(certs) ->
                    let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, this is the same as we sent in our extension
                    if Cert.is_chain_for_key_encryption certs then
                        let advice = Cert.validate_cert_chain allowedAlgs certs in
                        let advice =
                            match Cert.get_hint certs with
                            | None -> false
                            | Some(name) -> advice && (name = state.poptions.server_name)
                        InQuery(certs,advice,{state with pstate = PSClient(ClientCheckingCertificateRSA(si,log,certs,agreedVersion,to_log))})
                    else

                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Server sent wrong certificate type",state)

            | ServerCertificateDHE (si,log) ->
                match parseClientOrServerCertificate payload with
                | Error(x,y) ->

                    InError(x,y,state)

                | Correct(certs) ->
                    let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, this is the same as we sent in our extension
                    if Cert.is_chain_for_signing certs then
                        let advice = Cert.validate_cert_chain allowedAlgs certs in
                        let advice =
                            match Cert.get_hint certs with
                            | None -> false
                            | Some(name) -> advice && (name = state.poptions.server_name)
                        InQuery(certs,advice,{state with pstate = PSClient(ClientCheckingCertificateDHE(si,log,agreedVersion,to_log))})
                    else

                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Server sent wrong certificate type",state)

            | ServerCertificateDH (si,log) ->

                InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented",state)

            | _ ->

                InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Certificate arrived in the wrong state",state)

        | HT_server_key_exchange ->
            match cState with
            | ServerKeyExchangeDHE(si,log) ->
                match parseServerKeyExchange_DHE si.protocol_version si.cipher_suite payload with
                | Error(x,y) ->

                    InError(x,y,state)

                | Correct(v) ->
                    let (p,g,y,alg,signature) = v in
                    match Cert.get_chain_public_signing_key si.serverID alg with
                    | Error(x,y) ->

                        InError(x,y,state)

                    | Correct(vkey) ->
                    let dheb = dheParamBytes p g y in
                    let expected = si.init_crand @| si.init_srand @| dheb in
                    if Sig.verify alg vkey expected signature then
                        let log = log @| to_log in
                        recv_fragment_client ci
                          {state with pstate = PSClient(CertificateRequestDHE(si,p,g,y,log))}
                          agreedVersion
                    else
                        InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "",state)

            | ServerKeyExchangeDH_anon(si,log) ->
                match parseServerKeyExchange_DH_anon payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(v) ->
                    let (p,g,y) = v in
                    let log = log @| to_log in
                    recv_fragment_client ci
                      {state with pstate = PSClient(ServerHelloDoneDH_anon(si,p,g,y,log))}
                      agreedVersion
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerKeyExchange arrived in the wrong state",state)

        | HT_certificate_request ->
            match cState with
            | CertificateRequestRSA(si,log) ->
                (* Log the received packet *)
                let log = log @| to_log in

                (* Note: in next statement, use si, because the handshake runs according to the session we want to
                   establish, not the current one *)
                match parseCertificateRequest si.protocol_version payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(v) ->
                let (certType,alg,distNames) = v in
                let client_cert = find_client_cert_sign certType alg distNames si.protocol_version state.poptions.client_name in
                let si = {si with client_auth = true} in
                recv_fragment_client ci
                  {state with pstate = PSClient(ServerHelloDoneRSA(si,client_cert,log))}
                  agreedVersion
            | CertificateRequestDHE(si,p,g,y,log) ->
                // Duplicated code
                (* Log the received packet *)
                let log = log @| to_log in

                (* Note: in next statement, use si, because the handshake runs according to the session we want to
                   establish, not the current one *)
                match parseCertificateRequest si.protocol_version payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(v) ->
                let (certType,alg,distNames) = v in
                let client_cert = find_client_cert_sign certType alg distNames si.protocol_version state.poptions.client_name in
                let si = {si with client_auth = true} in
                recv_fragment_client ci
                  {state with pstate = PSClient(ServerHelloDoneDHE(si,client_cert,p,g,y,log))}
                  agreedVersion
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CertificateRequest arrived in the wrong state",state)

        | HT_server_hello_done ->
            match cState with
            | CertificateRequestRSA(si,log) ->
                if equalBytes payload [||] then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_RSA ci state si None log with
                    | Error (x,y) -> InError (x,y, state)
                    | Correct z ->
                        let (state,si,ms,log) = z in
                        recv_fragment_client ci
                          {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                          agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | ServerHelloDoneRSA(si,skey,log) ->
                if equalBytes payload [||] then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_RSA ci state si skey log with
                    | Error (x,y) -> InError (x,y, state)
                    | Correct z ->
                        let (state,si,ms,log) = z in
                        recv_fragment_client ci
                          {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                          agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | CertificateRequestDHE(si,p,g,y,log) | ServerHelloDoneDH_anon(si,p,g,y,log) ->
                if equalBytes payload [||] then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_DHE ci state si None p g y log with
                    | Error (x,y) -> InError (x,y, state)
                    | Correct z ->
                        let (state,si,ms,log) = z in
                        recv_fragment_client ci
                          {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                          agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | ServerHelloDoneDHE(si,skey,p,g,y,log) ->
                if equalBytes payload [||] then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_DHE ci state si skey p g y log with
                    | Error (x,y) -> InError (x,y, state)
                    | Correct z ->
                        let (state,si,ms,log) = z in
                        recv_fragment_client ci
                          {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                          agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerHelloDone arrived in the wrong state",state)

        | HT_finished ->
            match cState with
            | ServerFinished(si,ms,e,cvd,log) ->
                if PRF.checkVerifyData ci.id_in Server ms log payload then
                    let sDB =
                        if equalBytes si.sessionID [||] then state.sDB
                        else SessionDB.insert state.sDB (si.sessionID,Client,state.poptions.server_name) (si,ms)
                    check_negotiation Client si state.poptions;
                    InComplete({state with pstate = PSClient(ClientIdle(cvd,payload)); sDB = sDB})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | ServerFinishedResume(e,w,ms,log) ->
                if PRF.checkVerifyData ci.id_in Server ms log payload then
                    let log = log @| to_log in
                    InFinished({state with pstate = PSClient(ClientWritingCCSResume(e,w,ms,payload,log))})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Finished arrived in the wrong state",state)
        | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Unrecognized message",state)

      (* Should never happen *)
      | PSServer(_) -> unexpectedError "[recv_fragment_client] should only be invoked when in client role."

let prepare_server_output_full_RSA (ci:ConnectionInfo) state si cv calgs cvd svd log =
    let renInfo = cvd @| svd in
    let ext = extensionsBytes state.poptions.safe_renegotiation renInfo in
    let serverHelloB = serverHelloBytes si si.init_srand ext in
    match Cert.for_key_encryption calgs state.poptions.server_name with
    | None -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Could not find in the store a certificate for the negotiated ciphersuite")
    | Some(x) ->
        let (c,sk) = x in
        (* update server identity in the sinfo *)
        let si = {si with serverID = c} in
        let certificateB = serverCertificateBytes c in
        (* No ServerKEyExchange in RSA ciphersuites *)
        (* Compute the next state of the server *)
        if si.client_auth then
          let certificateRequestB = certificateRequestBytes true si.cipher_suite si.protocol_version in // true: Ask for sign-capable certificates
          let output = serverHelloB @| certificateB @| certificateRequestB @| serverHelloDoneBytes in
          (* Log the output and put it into the output buffer *)
          let log = log @| output in
          let ps = serverState ci (ClientCertificateRSA(si,cv,sk,log)) in
          correct ({state with hs_outgoing = output
                               pstate = ps},
                    si.protocol_version)
        else
          let output = serverHelloB @| certificateB @| serverHelloDoneBytes in
          (* Log the output and put it into the output buffer *)
          let log = log @| output in
          let ps = serverState ci (ClientKeyExchangeRSA(si,cv,sk,log)) in
          correct ({state with hs_outgoing = output
                               pstate = ps},
                    si.protocol_version)

let prepare_server_output_full_DH ci state si log =
    Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented")

let prepare_server_output_full_DHE (ci:ConnectionInfo) state si certAlgs cvd svd log =
    let renInfo = cvd @| svd in
    let ext = extensionsBytes state.poptions.safe_renegotiation renInfo in
    let serverHelloB = serverHelloBytes si si.init_srand ext in
    let keyAlgs = sigHashAlg_bySigList certAlgs [sigAlg_of_ciphersuite si.cipher_suite] in
    if listLength keyAlgs = 0 then
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "The client provided inconsistent signature algorithms and ciphersuites")
    else
    match Cert.for_signing certAlgs state.poptions.server_name keyAlgs with
    | None -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Could not find in the store a certificate for the negotiated ciphersuite")
    | Some(x) ->
        let (c,alg,sk) = x in
        (* set server identity in the session info *)
        let si = {si with serverID = c} in
        let certificateB = serverCertificateBytes c in
        (* ServerKEyExchange *)
        let (p,g) = DH.default_pp () in
        let (y,x) = DH.genKey p g in
        let dheb = dheParamBytes p g y in
        let toSign = si.init_crand @| si.init_srand @| dheb in
        let sign = Sig.sign alg sk toSign in
        let serverKEXB = serverKeyExchangeBytes_DHE dheb alg sign si.protocol_version in
        (* CertificateRequest *)
        if si.client_auth then
          let certificateRequestB = certificateRequestBytes true si.cipher_suite si.protocol_version in // true: Ask for sign-capable certificates
          let output = serverHelloB @| certificateB @| serverKEXB @| certificateRequestB @| serverHelloDoneBytes in
          (* Log the output and put it into the output buffer *)
          let log = log @| output in
          let ps = serverState ci (ClientCertificateDHE(si,p,g,y,x,log)) in
        (* Compute the next state of the server *)
            correct (
              {state with hs_outgoing = output
                          pstate = ps},
               si.protocol_version)
        else
          let output = serverHelloB @| certificateB @| serverKEXB @| serverHelloDoneBytes in
          (* Log the output and put it into the output buffer *)
          let log = log @| output in
          let ps = serverState ci (ClientKeyExchangeDHE(si,p,g,y,x,log)) in
            correct (
              {state with hs_outgoing = output
                          pstate = ps},
               si.protocol_version)

        (* ClientKeyExchangeDHE(si,p,g,x,log) should carry PP((p,g)) /\ ?gx. DHE.Exp((p,g),x,gx) *)

let prepare_server_output_full_DH_anon (ci:ConnectionInfo) state si cvd svd log =
    let renInfo = cvd @| svd in
    let ext = extensionsBytes state.poptions.safe_renegotiation renInfo in
    let serverHelloB = serverHelloBytes si si.init_srand ext in

    (* ServerKEyExchange *)
    let (p,g) = DH.default_pp () in
    let (y,x) = DH.genKey p g in
    let serverKEXB = serverKeyExchangeBytes_DH_anon p g y in

    let output = serverHelloB @|serverKEXB @| serverHelloDoneBytes in
    (* Log the output and put it into the output buffer *)
    let log = log @| output in
    (* Compute the next state of the server *)
    let ps = serverState ci (ClientKeyExchangeDH_anon(si,p,g,y,x,log)) in
    correct ({state with hs_outgoing = output
                         pstate = ps},
             si.protocol_version)

let prepare_server_output_full ci state si cv cvd svd log =
    if isAnonCipherSuite si.cipher_suite then
        prepare_server_output_full_DH_anon ci state si cvd svd log
    elif isDHCipherSuite si.cipher_suite then
        prepare_server_output_full_DH ci state si log
    elif isDHECipherSuite si.cipher_suite then
        // Get the client supported SignatureAndHash algorithms. In TLS 1.2, this should be extracted from a client extension
        let calgs = default_sigHashAlg si.protocol_version si.cipher_suite in
        prepare_server_output_full_DHE ci state si calgs cvd svd log
    elif isRSACipherSuite si.cipher_suite then
        // Get the client supported SignatureAndHash algorithms. In TLS 1.2, this should be extracted from a client extension
        let calgs = default_sigHashAlg si.protocol_version si.cipher_suite in
        prepare_server_output_full_RSA ci state si cv calgs cvd svd log
    else
        unexpectedError "[prepare_server_output_full] unexpected ciphersuite"

// The server "negotiates" its first proposal included in the client's proposal
let negotiate cList sList =
    Bytes.tryFind (fun s -> Bytes.exists (fun c -> c = s) cList) sList

let prepare_server_output_resumption ci state crand si ms cvd svd log =
    let srand = Nonce.mkHelloRandom () in
    let renInfo = cvd @| svd in
    let ext = extensionsBytes state.poptions.safe_renegotiation renInfo in
    let sHelloB = serverHelloBytes si srand ext in

    let log = log @| sHelloB
    let next_ci = getNextEpochs ci si crand srand in
    let (writer,reader) = PRF.keyGen next_ci ms in
    {state with hs_outgoing = sHelloB
                pstate = PSServer(ServerWritingCCSResume(next_ci.id_out,writer,
                                                         next_ci.id_in,reader,
                                                         ms,log))}

let startServerFull (ci:ConnectionInfo) state (cHello:ProtocolVersion * crand * sessionID * cipherSuites * Compression list * bytes) cvd svd log =
    let (ch_client_version,ch_random,ch_session_id,ch_cipher_suites,ch_compression_methods,ch_extensions) = cHello in
    let cfg = state.poptions in
    // Negotiate the protocol parameters
    let version = minPV ch_client_version cfg.maxVer in
    if (geqPV version cfg.minVer) = false then
        Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation")
    else
        match negotiate ch_cipher_suites cfg.ciphersuites with
        | Some(cs) ->
            match negotiate ch_compression_methods cfg.compressions with
            | Some(cm) ->
                let sid = random 32 in
                let srand = Nonce.mkHelloRandom () in
                (* Fill in the session info we're establishing *)
                let si = { clientID         = []
                           client_auth      = cfg.request_client_certificate
                           serverID         = []
                           sessionID        = sid
                           protocol_version = version
                           cipher_suite     = cs
                           compression      = cm
                           init_crand       = ch_random
                           init_srand       = srand
                           pmsData          = PMSUnset
                           extended_record_padding = false }
                prepare_server_output_full ci state si ch_client_version cvd svd log
            | None -> Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation")
        | None ->     Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation")

let rec recv_fragment_server (ci:ConnectionInfo) (state:hs_state) (agreedVersion:ProtocolVersion option) =
    match parseMessageState ci state with
    | Error(x,y) -> InError(x,y,state)
    | Correct(res) ->
      match res with
      | None ->
          match agreedVersion with
          | None      -> InAck(state)
          | Some (pv) -> InVersionAgreed(state,pv)
      | Some (res) ->
      let (state,hstype,payload,to_log) = res in
      match state.pstate with
      | PSServer(sState) ->
        match hstype with
        | HT_client_hello ->
            match sState with
            | ClientHello(cvd,svd) | ServerIdle(cvd,svd) ->
                match parseClientHello payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct (cHello) ->
                let (ch_client_version,ch_random,ch_session_id,ch_cipher_suites,ch_compression_methods,ch_extensions) = cHello
                (* Log the received message *)
                let log = to_log in
                (* handle extensions: for now only renegotiation_info *)
                match parseExtensions ch_extensions with
                | Error(x,y) -> InError(x,y,state)
                | Correct(extList) ->
                let extRes =
                    if state.poptions.safe_renegotiation then
                        if checkClientRenegotiationInfoExtension extList ch_cipher_suites cvd then
                            correct(state)
                        else
                            (* We don't accept an insecure client *)
                            Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Safe renegotiation not supported by the peer")
                    else
                        (* We can ignore the extension, if any *)
                        correct(state)
                match extRes with
                | Error(x,y) -> InError(x,y,state)
                | Correct(state) ->
                    if equalBytes ch_session_id [||]
                    then
                        (* Client asked for a full handshake *)
                        match startServerFull ci state cHello cvd svd log with
                        | Error(x,y) -> InError(x,y,state)
                        | Correct(v) ->
                            let (state,pv) = v in
                            let spv = somePV pv in
                              recv_fragment_server ci state spv
                    else
                        (* Client asked for resumption, let's see if we can satisfy the request *)
                        match SessionDB.select state.sDB (ch_session_id,Server,state.poptions.client_name) with
                        | Some sentry ->
                            let (storedSinfo,storedMS)  = sentry in
                            if geqPV ch_client_version storedSinfo.protocol_version
                              && Bytes.memr ch_cipher_suites storedSinfo.cipher_suite
                              && Bytes.memr ch_compression_methods storedSinfo.compression
                            then
                              (* Proceed with resumption *)
                              let state = prepare_server_output_resumption ci state ch_random storedSinfo storedMS cvd svd log in
                              recv_fragment_server ci state (somePV(storedSinfo.protocol_version))
                            else
                              match startServerFull ci state cHello cvd svd log with
                                | Correct(v) -> let (state,pv) = v in recv_fragment_server ci state (somePV (pv))
                                | Error(x,y) -> InError(x,y,state)
                        | None ->
                              match startServerFull ci state cHello cvd svd log with
                                | Correct(v) -> let (state,pv) = v in recv_fragment_server ci state (somePV (pv))
                                | Error(x,y) -> InError(x,y,state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ClientHello arrived in the wrong state",state)

        | HT_certificate ->
            match sState with
            | ClientCertificateRSA (si,cv,sk,log) ->
                match parseClientOrServerCertificate payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(certs) ->
                    if Cert.is_chain_for_signing certs then
                        let advice = Cert.validate_cert_chain (default_sigHashAlg si.protocol_version si.cipher_suite) certs in
                        match Cert.get_hint certs with
                            | None ->
                                InQuery(certs,false,
                                        {state with pstate = PSServer(ServerCheckingCertificateRSA(si,cv,sk,log,certs,to_log))})
                            | Some(name) when advice && (name = state.poptions.client_name) ->
                                InQuery(certs,true,
                                        {state with pstate = PSServer(ServerCheckingCertificateRSA(si,cv,sk,log,certs,to_log))})
                            | Some(name) ->
                                InQuery(certs,false,
                                        {state with pstate = PSServer(ServerCheckingCertificateRSA(si,cv,sk,log,certs,to_log))})
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Client sent wrong certificate type",state)
            | ClientCertificateDHE (si,p,g,gx,x,log) ->
                // Duplicated code from above.
                match parseClientOrServerCertificate payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(certs) ->
                    if Cert.is_chain_for_signing certs then
                        let advice = Cert.validate_cert_chain (default_sigHashAlg si.protocol_version si.cipher_suite) certs in
                        match Cert.get_hint certs with
                            | None ->
                                InQuery(certs,false,{state with pstate = PSServer(ServerCheckingCertificateDHE(si,p,g,gx,x,log,certs,to_log))})
                            | Some(name) when advice && (name = state.poptions.client_name) ->
                                InQuery(certs,true,{state with pstate = PSServer(ServerCheckingCertificateDHE(si,p,g,gx,x,log,certs,to_log))})
                            | Some(name) ->
                                InQuery(certs,false,{state with pstate = PSServer(ServerCheckingCertificateDHE(si,p,g,gx,x,log,certs,to_log))})
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Client sent wrong certificate type",state)
            | ClientCertificateDH  (si,log) ->  InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Certificate arrived in the wrong state",state)

        | HT_client_key_exchange ->
            match sState with
            | ClientKeyExchangeRSA(si,cv,sk,log) ->
                match parseClientKEX_RSA si sk cv state.poptions payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(res) ->
                    let (pmsdata,pms) = res in
                    let si = {si with pmsData = pmsdata} in
                    let log = log @| to_log in
                    let ms = CRE.prfSmoothRSA si cv pms in

                    (* move to new state *)
                    if si.client_auth then
#if verify
                        Pi.expect(ServerLogBeforeClientCertificateVerifyRSA(si,log));
                        Pi.expect(Authorize(Server,si));
                        Pi.expect(ServerLogBeforeClientCertificateVerify(si,log));
#endif
                        recv_fragment_server ci
                          {state with pstate = PSServer(CertificateVerify(si,ms,log))}
                          agreedVersion
                    else
                        recv_fragment_server ci
                          {state with pstate = PSServer(ClientCCS(si,ms,log))}
                          agreedVersion
            | ClientKeyExchangeDHE(si,p,g,gx,x,log) ->
                match parseClientKEXExplicit_DH p payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(y) ->
                    let log = log @| to_log in
                    let si = {si with pmsData = DHPMS(p,g,y,gx)} in
                    (* from the local state, we know: PP((p,g)) /\ ?gx. DHE.Exp((p,g),x,gx) ; tweak the ?gx for genPMS. *)
                    let pms = DH.exp p g gx y x in
                    (* StrongHS(si) /\ DHE.Exp((p,g),?cx,y) -> DHE.Secret(pms) *)
                    let ms = CRE.prfSmoothDHE si p g gx y pms in
                    (* StrongHS(si) /\ DHE.Exp((p,g),?cx,y) -> PRFs.Secret(ms) *)

                    (* we rely on scopes & type safety to get forward secrecy*)
                    (* move to new state *)
                    if si.client_auth then
#if verify
                        Pi.expect(ServerLogBeforeClientCertificateVerifyDHE(si,log));
                        Pi.expect(Authorize(Server,si));
                        Pi.expect(ServerLogBeforeClientCertificateVerify(si,log));
#endif
                        recv_fragment_server ci
                          {state with pstate = PSServer(CertificateVerify(si,ms,log))}
                          agreedVersion
                    else
                        recv_fragment_server ci
                          {state with pstate = PSServer(ClientCCS(si,ms,log))}
                          agreedVersion
#if verify
#else
            | ClientKeyExchangeDH_anon(si,p,g,gx,x,log) ->
                match parseClientKEXExplicit_DH p payload with
                | Error(x,y) -> InError(x,y,state)
                | Correct(y) ->
                    let log = log @| to_log in
                    let pms = DH.exp p g gx y x in
                    let ms = CRE.prfSmoothDHE si p g gx y pms in

                    (* move to new state *)
                    recv_fragment_server ci
                      {state with pstate = PSServer(ClientCCS(si,ms,log))}
                      agreedVersion
#endif
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ClientKeyExchange arrived in the wrong state",state)

        | HT_certificate_verify ->
            match sState with
            | CertificateVerify(si,ms,log) ->
                let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, these are the same as we sent in CertificateRequest
                let (verifyOK,_) = certificateVerifyCheck si ms allowedAlgs log payload in
                if verifyOK then// payload then
                    let log = log @| to_log in
#if verify
                        Pi.expect(ServerLogBeforeClientFinished(si,log));
                        Pi.expect(Authorize(Server,si));
#endif
                    recv_fragment_server ci
                      {state with pstate = PSServer(ClientCCS(si,ms,log))}
                      agreedVersion
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Certificate verify check failed",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CertificateVerify arrived in the wrong state",state)

        | HT_finished ->
            match sState with
            | ClientFinished(si,ms,e,w,log) ->
                if PRF.checkVerifyData ci.id_in Client ms log payload then
                    let log = log @| to_log in
                    InFinished({state with pstate = PSServer(ServerWritingCCS(si,ms,e,w,payload,log))})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | ClientFinishedResume(si,ms,e,svd,log) ->
                if PRF.checkVerifyData ci.id_in Client ms log payload then
                    check_negotiation Server si state.poptions;
                    InComplete({state with pstate = PSServer(ServerIdle(payload,svd))})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Finished arrived in the wrong state",state)

        | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Unknown message received",state)
      (* Should never happen *)
      | PSClient(_) -> unexpectedError "[recv_fragment_server] should only be invoked when in server role."

let enqueue_fragment (ci:ConnectionInfo) state fragment =
    let new_inc = state.hs_incoming @| fragment in
    {state with hs_incoming = new_inc}

let recv_fragment ci (state:hs_state) (r:range) (fragment:HSFragment.fragment) =

    let b = HSFragment.fragmentRepr ci.id_in r fragment in
    if length b = 0 then
        // Empty HS fragment are not allowed
        InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Empty handshake fragment received",state)
    else
        let state = enqueue_fragment ci state b in
        match state.pstate with
        | PSClient (_) -> recv_fragment_client ci state None
        | PSServer (_) -> recv_fragment_server ci state None

let recv_ccs (ci:ConnectionInfo) (state: hs_state) (r:range) (fragment:HSFragment.fragment): incomingCCS =

    let b = HSFragment.fragmentRepr ci.id_in r fragment in
    if equalBytes b CCSBytes then
        match state.pstate with
        | PSClient (cstate) -> // Check that we are in the right state (CCCS)
            match cstate with
            | ServerCCS(si,ms,e,r,cvd,log) ->
                let ci = {ci with id_in = e} in
                InCCSAck(ci,r,{state with pstate = PSClient(ServerFinished(si,ms,e,cvd,log))})
            | ServerCCSResume(ew,w,er,r,ms,log) ->
                let ci = {ci with id_in = er} in
                InCCSAck(ci,r,{state with pstate = PSClient(ServerFinishedResume(ew,w,ms,log))})
            | _ -> InCCSError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CCS arrived in the wrong state",state)
        | PSServer (sState) ->
            match sState with
            | ClientCCS(si,ms,log) ->
                let next_ci = getNextEpochs ci si si.init_crand si.init_srand in
                let (writer,reader) = PRF.keyGen next_ci ms in
                let ci = {ci with id_in = next_ci.id_in} in
                InCCSAck(ci,reader,{state with pstate = PSServer(ClientFinished(si,ms,next_ci.id_out,writer,log))})
            | ClientCCSResume(e,r,svd,ms,log) ->
                let ci = {ci with id_in = e} in
                InCCSAck(ci,r,{state with pstate = PSServer(ClientFinishedResume(epochSI e,ms,e,svd,log))})
            | _ -> InCCSError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CCS arrived in the wrong state",state)
    else           InCCSError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)

let getMinVersion (ci:ConnectionInfo) state =
  let pop = state.poptions in
  pop.minVer

let authorize (ci:ConnectionInfo) (state:hs_state) (q:Cert.chain) =
    let pstate = state.pstate in
    match pstate with
    | PSClient(cstate) ->
        match cstate with
        | ClientCheckingCertificateRSA(si,log,certs,agreedVersion,to_log) ->
            if certs = q then
              let log = log @| to_log in
              let si = {si with serverID = q} in
              Pi.assume (Authorize(Client,si));
              recv_fragment_client ci
                {state with pstate = PSClient(CertificateRequestRSA(si,log))}
                agreedVersion
            else unexpectedError "[authorize] invoked with different cert"
        | ClientCheckingCertificateDHE(si,log,agreedVersion,to_log) ->
            let log = log @| to_log in
            let si = {si with serverID = q} in
            Pi.assume (Authorize(Client,si));
            recv_fragment_client ci
              {state with pstate = PSClient(ServerKeyExchangeDHE(si,log))}
              agreedVersion
        // | ClientCheckingCertificateDH -> TODO
        | _ -> unexpectedError "[authorize] invoked on the wrong state"
    | PSServer(sstate) ->
        match sstate with
        | ServerCheckingCertificateRSA(si,cv,sk,log,c,to_log) when c = q ->
            let log = log @| to_log in
            let si = {si with clientID = q} in
             Pi.assume (Authorize(Server,si));
            recv_fragment_server ci
              {state with pstate = PSServer(ClientKeyExchangeRSA(si,cv,sk,log))}
              None
        | ServerCheckingCertificateDHE(si,p,g,gx,x,log,c,to_log) when c = q ->
            let log = log @| to_log in
            let si = {si with clientID = q} in
            Pi.assume (Authorize(Server,si));
            recv_fragment_server ci
              {state with pstate = PSServer(ClientKeyExchangeDHE(si,p,g,gx,x,log))}
              None
        // | ServerCheckingCertificateDH -> TODO
        | _ -> unexpectedError "[authorize] invoked on the wrong state"

(* function used by an ideal handshake implementation to decide whether to idealize keys
let safe ki =
    match (CS(ki), Honest(LTKey(ki, Server)), Honest(LTKey(ki,Client))) with
    | (CipherSuite (RSA, MtE (AES_256_CBC, SHA256)), true, _) -> pmsGenerated ki
    | (CipherSuite (DHE_DSS, MtE (AES_256_CBC, SHA)), _, _) ->
        if (TcGenerated ki) && (TsGenerated ki) then
            true
        else
            false
    | _ -> false

 *)
