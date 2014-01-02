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

(* Handshake protocol messages *)
module HandshakeMessages

open Bytes
open Error
open TLSError
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
    | HT_hello_request       -> abyte   0uy
    | HT_client_hello        -> abyte   1uy
    | HT_server_hello        -> abyte   2uy
    | HT_certificate         -> abyte  11uy
    | HT_server_key_exchange -> abyte  12uy
    | HT_certificate_request -> abyte  13uy
    | HT_server_hello_done   -> abyte  14uy
    | HT_certificate_verify  -> abyte  15uy
    | HT_client_key_exchange -> abyte  16uy
    | HT_finished            -> abyte  20uy

let parseHt (b:bytes) =
    match cbyte b with
    |   0uy  -> correct(HT_hello_request      )
    |   1uy  -> correct(HT_client_hello       )
    |   2uy  -> correct(HT_server_hello       )
    |  11uy  -> correct(HT_certificate        )
    |  12uy  -> correct(HT_server_key_exchange)
    |  13uy  -> correct(HT_certificate_request)
    |  14uy  -> correct(HT_server_hello_done  )
    |  15uy  -> correct(HT_certificate_verify )
    |  16uy  -> correct(HT_client_key_exchange)
    |  20uy  -> correct(HT_finished           )
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
        | Error z ->  Error z
        | Correct(hstype) ->
            match vlsplit 3 rem with
            | Error z -> Correct(None) // not enough payload, try next time
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
    let i = id ki in
    if length b < fragmentLength then
      let r0 = (length b, length b) in
      let f = HSFragment.fragmentPlain i r0 b in
      (r0,f,empty_bytes)
    else
      let (b0,rem) = Bytes.split b fragmentLength in
      let r0 = (length b0, length b0) in
      let f = HSFragment.fragmentPlain i r0 b0 in
      (r0,f,rem)

// we could use something more general for parsing lists, e.g.
// let rec parseList parseOne b =
//     if length b = 0 then correct([])
//     else
//     match parseOne b with
//     | Correct(x,b) ->
//         match parseList parseOne b with
//         | Correct(xs) -> correct(x::xs)
//         | Error z -> Error z
//     | Error z -> Error z

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
        | Error z -> Error z
        | Correct(cv) ->
        if length data >= 1 then
            match vlsplit 1 data with
            | Error z -> Error z
            | Correct (res) ->
            let (sid,data) = res in
            if length sid <= 32 then
                if length data >= 2 then
                    match vlsplit 2 data with
                    | Error z -> Error z
                    | Correct (res) ->
                    let (clCiphsuitesBytes,data) = res in
                    match parseCipherSuites clCiphsuitesBytes with
                    | Error(z) -> Error(z)
                    | Correct (clientCipherSuites) ->
                    if length data >= 1 then
                        match vlsplit 1 data with
                        | Error(z) -> Error(z)
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
        | Error z -> Error z
        | Correct(serverVer) ->
        if length data >= 1 then
            match vlsplit 1 data with
            | Error z -> Error z
            | Correct (res) ->
            let (sid,data) = res in
            if length sid <= 32 then
                if length data >= 3 then
                    let (csBytes,cmBytes,data) = split2 data 2 1
                    match parseCipherSuite csBytes with
                    | Error(z) -> Error(z)
                    | Correct(cs) ->
                    match parseCompression cmBytes with
                    | Error(z) -> Error(z)
                    | Correct(cm) ->
                    correct(serverVer,serverRandomBytes,sid,cs,cm,data)
                else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let helloRequestBytes = messageBytes HT_hello_request empty_bytes

let CCSBytes = abyte 1uy

(** A.4.2 Server Authentication and Key Exchange Messages *)

let serverHelloDoneBytes = messageBytes HT_server_hello_done empty_bytes

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
        | Error z -> let (x,y) = z in Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ y)
        | Correct (certList) -> Cert.parseCertificateList certList []
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let sigHashAlgBytesVersion version cs =
     match version with
        | TLS_1p2 ->
            let defaults = default_sigHashAlg version cs in
            let res = sigHashAlgListBytes defaults in
            vlbytes 2 res
        | TLS_1p1 | TLS_1p0 | SSL_3p0 -> empty_bytes

let parseSigHashAlgVersion version data =
    match version with
    | TLS_1p2 ->
        if length data >= 2 then
            match vlsplit 2 data with
            | Error(z) -> Error(z)
            | Correct (res) ->
            let (sigAlgsBytes,data) = res in
            match parseSigHashAlgList sigAlgsBytes with
            | Error(z) -> Error(z)
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
        | Error(z) -> Error(z)
        | Correct (res) ->
        let (certTypeListBytes,data) = res in
        match parseCertificateTypeList certTypeListBytes with
        | Error(z) -> Error(z)
        | Correct(certTypeList) ->
        match parseSigHashAlgVersion version data with
        | Error(z) -> Error(z)
        | Correct (res) ->
        let (sigAlgs,data) = res in
        if length data >= 2 then
            match vlparse 2 data with
            | Error(z) -> Error(z)
            | Correct  (distNamesBytes) ->
            let el = [] in
            match parseDistinguishedNameList distNamesBytes el with
            | Error(z) -> Error(z)
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
            | Error(z) -> Error(z)
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let clientKEXBytes_RSA si config =
    if List.listLength si.serverID = 0 then
        unexpected "[clientKEXBytes_RSA] Server certificate should always be present with a RSA signing cipher suite."
    else
        match Cert.get_chain_public_encryption_key si.serverID with
        | Error(z) -> Error(z)
        | Correct(pubKey) ->
            let pms = PMS.genRSA pubKey config.maxVer in
            let encpms = RSA.encrypt pubKey config.maxVer pms in
            let nencpms = encpmsBytesVersion si.protocol_version encpms in
            let mex = messageBytes HT_client_key_exchange nencpms in
            let pmsdata = RSAPMS(pubKey,config.maxVer,encpms) in
            correct(mex,pmsdata,pms)

let parseClientKEX_RSA si skey cv config data =
    if List.listLength si.serverID = 0 then
        unexpected "[parseClientKEX_RSA] when the ciphersuite can encrypt the PMS, the server certificate should always be set"
    else
        match parseEncpmsVersion si.protocol_version data with
        | Correct(encPMS) ->
            let res = RSA.decrypt skey si cv config.check_client_version_in_pms_for_old_tls encPMS in
            let (Correct(pk)) = Cert.get_chain_public_encryption_key si.serverID in
            correct(RSAPMS(pk,cv,encPMS),res)
        | Error(z) -> Error(z)

let clientKEXExplicitBytes_DH y =
    let yb = vlbytes 2 y in
    messageBytes HT_client_key_exchange yb

let parseClientKEXExplicit_DH p data =
    if length data >= 2 then
        match vlparse 2 data with
        | Error(z) -> Error(z)
        | Correct(y) ->
            match DHGroup.checkElement p y with
            | None -> Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid DH key received")
            | Some(y) -> correct y
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

// Unused until we don't support DH ciphersuites.
let clientKEXImplicitBytes_DH = messageBytes HT_client_key_exchange empty_bytes
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
            | Error(z) -> Error(z)
            | Correct(recvAlgs) ->
                if sigHashAlg_contains expectedAlgs recvAlgs then
                    if length sign >= 2 then
                        match vlparse 2 sign with
                        | Error(z) -> Error(z)
                        | Correct(sign) -> correct(recvAlgs,sign)
                    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
                else Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | SSL_3p0 | TLS_1p0 | TLS_1p1 ->
        if List.listLength expectedAlgs = 1 then
            if length payload >= 2 then
                match vlparse 2 payload with
                | Error(z) -> Error(z)
                | Correct(sign) ->
                correct(List.listHead expectedAlgs,sign)
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else unexpected "[parseDigitallySigned] invoked with invalid SignatureAndHash algorithms"

(* Server Key exchange *)

let dheParamBytes p g y = (vlbytes 2 p) @| (vlbytes 2 g) @| (vlbytes 2 y)
let parseDHEParams payload =
    if length payload >= 2 then
        match vlsplit 2 payload with
        | Error(z) -> Error(z)
        | Correct(res) ->
        let (p,payload) = res in
        if length payload >= 2 then
            match vlsplit 2 payload with
            | Error(z) -> Error(z)
            | Correct(res) ->
            let (g,payload) = res in
            if length payload >= 2 then
                match vlsplit 2 payload with
                | Error(z) -> Error(z)
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
    | Error(z) -> Error(z)
    | Correct(res) ->
        let (p,g,y,payload) = res
        let allowedAlgs = default_sigHashAlg pv cs in
        match parseDigitallySigned allowedAlgs payload pv with
        | Error(z) -> Error(z)
        | Correct(res) ->
            let (alg,signature) = res
            correct(p,g,y,alg,signature)

let serverKeyExchangeBytes_DH_anon p g y =
    let dehb = dheParamBytes p g y in
    messageBytes HT_server_key_exchange dehb

let parseServerKeyExchange_DH_anon payload =
    match parseDHEParams payload with
    | Error(z) -> Error(z)
    | Correct(p,g,y,rem) ->
        if length  rem = 0 then
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
            | Error(z) -> (false,empty_bytes)
            | Correct(vkey) ->
                let res = Sig.verify alg vkey log signature in
                (res,signature)
        | SSL_3p0 ->
            let (sigAlg,_) = alg in
            let alg = (sigAlg,NULL) in
            let expected = PRF.ssl_certificate_verify si ms sigAlg log in
            match Cert.get_chain_public_signing_key si.clientID alg with
            | Error(z) -> (false,empty_bytes)
            | Correct(vkey) ->
                let res = Sig.verify alg vkey expected signature in
                (res,signature)
    | Error(z) -> (false,empty_bytes)
