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

module Handshake
// State machine begins
open Bytes
open CoreKeys
open Error
open TLSError
open TLSConstants
open TLSInfo
open TLSExtensions
open Range
open HandshakeMessages

// the ``#if verify'' compilation is set for F7 typechecking but not F# compilation
// it is used to isolate dynamic assumes and expects, which only affect the logic
// and to elide code for ciphersuites we don't verify yet

type events =
    | Authorize of Role * SessionInfo
    | Configure of Role * epoch * config
    | EvSentFinishedFirst of ConnectionInfo * bool
    | Negotiated of Role * SessionInfo * config * config

     // the next three predicates are never assumed, except for logical debugging
    | CompleteEpoch of Role * epoch
    | Complete of ConnectionInfo
    | LMsg of Sig.alg * Sig.skey * Sig.text
    | LClientFinishedResume of epoch * bytes // for testing
    | Unreachable of unit // for testing

(* verify data authenticated by the Finished messages *)
type log = bytes         (* message payloads so far, to be eventually authenticated *)

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

   | ClientCertificateDHE         of SessionInfo * dhparams * DHGroup.elt * DH.secret * log
   | ServerCheckingCertificateDHE of SessionInfo * dhparams * DHGroup.elt * DH.secret * log * Cert.chain * bytes
   | ClientKeyExchangeDHE         of SessionInfo * dhparams * DHGroup.elt * DH.secret * log

   | ClientKeyExchangeDH_anon     of SessionInfo * dhparams * DHGroup.elt * DH.secret * log

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
   | ServerHello                  of crand * sessionID * list<clientExtension> * cVerifyData * sVerifyData * log

   | ServerCertificateRSA         of SessionInfo * log
   | ClientCheckingCertificateRSA of SessionInfo * log * list<Cert.cert> * option<ProtocolVersion> * bytes
   | CertificateRequestRSA        of SessionInfo * log (* In fact, CertReq or SHelloDone will be accepted *)
   | ServerHelloDoneRSA           of SessionInfo * Cert.sign_cert * log

   | ServerCertificateDH          of SessionInfo * log
   | ClientCheckingCertificateDH  of SessionInfo * log * option<ProtocolVersion> * bytes
   | CertificateRequestDH         of SessionInfo * log (* We pick our cert and store it in sessionInfo as soon as the server requests it.
                                                         We put None if we don't have such a certificate, and we know whether to send
                                                         the Certificate message or not based on the state when we receive the Finished message *)
   | ServerHelloDoneDH            of SessionInfo * log

   | ServerCertificateDHE         of SessionInfo * log
   | ClientCheckingCertificateDHE of SessionInfo * log * list<Cert.cert> * option<ProtocolVersion> * bytes
   | ServerKeyExchangeDHE         of SessionInfo * log
   | CertificateRequestDHE        of SessionInfo * dhparams * DHGroup.elt * log
   | ServerHelloDoneDHE           of SessionInfo * Cert.sign_cert * dhparams * DHGroup.elt * log

   | ServerKeyExchangeDH_anon of SessionInfo * log (* Not supported yet *)
   | ServerHelloDoneDH_anon of SessionInfo * dhparams * DHGroup.elt * log

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
  (* Session and DH DBs *)
  sDB: SessionDB.t;
  dhdb: DHDB.dhdb;
  (* current handshake & session we are establishing *)
  pstate: protoState;
}

type nextState = hs_state

/// Initiating Handshakes, mostly on the client side.

let init (role:Role) poptions =
    (* Start a new session without resumption, as the first epoch on this connection. *)
    let sid = empty_bytes in
    let rand = Nonce.mkHelloRandom() in
    match role with
    | Client ->
        let ci = initConnection role rand in
        Pi.assume (Configure(Client,ci.id_in,poptions)); // ``The user starts a client in this config''
        let extL = prepareClientExtensions poptions ci empty_bytes in
        let ext = clientExtensionsBytes extL in
        let cHelloBytes = clientHelloBytes poptions rand sid ext in
        let sdb = SessionDB.create poptions in
        let dhdb = DHDB.create poptions.dhDBFileName in
        (ci,{hs_outgoing = cHelloBytes;
                     hs_incoming = empty_bytes;
                     poptions = poptions;
                     sDB = sdb;
                     dhdb = dhdb;
                     pstate = PSClient (ServerHello (rand, sid, extL, empty_bytes, empty_bytes, cHelloBytes))
            })
    | Server ->
        let ci = initConnection role rand in
        Pi.assume (Configure(Server,ci.id_in,poptions)); // ``The user starts a server in this config''
        let sdb = SessionDB.create poptions in
        let dhdb = DHDB.create poptions.dhDBFileName in
        (ci,{hs_outgoing = empty_bytes;
             hs_incoming = empty_bytes;
             poptions = poptions;
             sDB = sdb;
             dhdb = dhdb;
             pstate = PSServer (ClientHello(empty_bytes,empty_bytes))
            })

let resume next_sid poptions =
    (* Resume a session, as the first epoch on this connection.
       Set up our state as a client. Servers cannot resume *)

    (* Search a client sid in the DB *)
    let sDB = SessionDB.create poptions in
    match SessionDB.select sDB next_sid Client poptions.server_name with
    | None -> init Client poptions
    | Some (retrieved) ->
    let (retrievedSinfo,retrievedMS) = retrieved in
    match retrievedSinfo.sessionID with
    | xx when length xx = 0 -> unexpected "[resume] a resumed session should always have a valid sessionID"
    | sid ->
    if hasExtendedMS retrievedSinfo.extensions then
        // we try to resume
        let rand = Nonce.mkHelloRandom () in
        let ci = initConnection Client rand in
        Pi.assume (Configure(Client,ci.id_in,poptions)); // ``The user resumes a client in this config''
        let extL = prepareClientExtensions poptions ci empty_bytes in
        let ext = clientExtensionsBytes extL in
        let cHelloBytes = clientHelloBytes poptions rand sid ext in
        let sdb = SessionDB.create poptions in
        let dhdb = DHDB.create poptions.dhDBFileName in
        (ci,{hs_outgoing = cHelloBytes;
             hs_incoming = empty_bytes;
             poptions = poptions;
             sDB = sdb;
             dhdb = dhdb;
             pstate = PSClient (ServerHello (rand, sid, extL, empty_bytes, empty_bytes, cHelloBytes))
            })
    else
        // The session we're trying to resume doesn't support extended master secret, hence we don't resume it
        init Client poptions

let rehandshake (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    (* Start a non-resuming handshake, over an existing epoch.
       Only client side, since a server can only issue a HelloRequest *)
    match state.pstate with
    | PSClient (cstate) ->
        (match cstate with
        | ClientIdle(cvd,svd) ->
            (let rand = Nonce.mkHelloRandom () in
            let sid = empty_bytes in
            let extL = prepareClientExtensions ops ci cvd in
            let ext = clientExtensionsBytes extL in
            let cHelloBytes = clientHelloBytes ops rand sid ext in
            Pi.assume (Configure(Client,ci.id_in,ops)); // ``The user renegotiates a client in this config''
            let sdb = SessionDB.create ops in
            let dhdb = DHDB.create ops.dhDBFileName in
            (true,{hs_outgoing = cHelloBytes;
                   hs_incoming = empty_bytes;
                   poptions = ops;
                   sDB = sdb;
                   dhdb = dhdb;
                   pstate = PSClient (ServerHello (rand, sid, extL, cvd,svd, cHelloBytes))
                   }))
        | _ -> (* handshake already happening, ignore this request *)
            (false,state))
    | PSServer (_) -> unexpected "[rehandshake] should only be invoked on client side connections."

let rekey (ci:ConnectionInfo) (state:hs_state) (ops:config) : bool * hs_state =
#if verify
  failwith "unverified for now"
#else
    if isInitEpoch(ci.id_out) then
        unexpected "[rekey] should only be invoked on established connections."
    else
    (* Start a (possibly) resuming handshake over an existing epoch *)
    let si = epochSI(ci.id_out) in // or equivalently ci.id_in
    let sidOp = si.sessionID in
    match sidOp with
    | xx when length xx = 0 -> (* Non resumable session, let's do a full handshake *)
        rehandshake ci state ops
    | sid ->
        let sDB = SessionDB.create ops in
        (* Ensure the sid is in the SessionDB *)
        (match SessionDB.select sDB sid Client ops.server_name with
        | None -> (* Maybe session expired, or was never stored. Let's not resume *)
            rehandshake ci state ops
        | Some s ->
            let (retrievedSinfo,retrievedMS) = s in
            if hasExtendedMS retrievedSinfo.extensions then
                match state.pstate with
                | PSClient (cstate) ->
                    (match cstate with
                    | ClientIdle(cvd,svd) ->
                        (let rand = Nonce.mkHelloRandom () in
                        let extL = prepareClientExtensions ops ci cvd in
                        let ext = clientExtensionsBytes extL in
                        Pi.assume (Configure(Client,ci.id_in,ops)); // ``The user rekeys a client in this config''
                        let cHelloBytes = clientHelloBytes ops rand sid ext in
                        let dhdb = DHDB.create ops.dhDBFileName in
                        (true,{hs_outgoing = cHelloBytes;
                               hs_incoming = empty_bytes;
                               poptions = ops;
                               sDB = sDB;
                               dhdb = dhdb;
                               pstate = PSClient (ServerHello (rand, sid, extL, cvd, svd, cHelloBytes))
                               }))
                    | _ -> (* Handshake already ongoing, ignore this request *)
                        (false,state))
                | PSServer (_) -> unexpected "[rekey] should only be invoked on client side connections."
            else
                // Don't resume a non extended-master-secret session
                rehandshake ci state ops)
#endif

let request (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    match state.pstate with
    | PSClient _ -> unexpected "[request] should only be invoked on server side connections."
    | PSServer (sstate) ->
        (match sstate with
        | ServerIdle(cvd,svd) ->
            let sdb = SessionDB.create ops in
            let dhdb = DHDB.create ops.dhDBFileName in
            (* Put HelloRequest in outgoing buffer (and do not log it), and move to the ClientHello state (so that we don't send HelloRequest again) *)
            (true, { hs_outgoing = helloRequestBytes;
                     hs_incoming = empty_bytes;
                     poptions = ops;
                     sDB = sdb;
                     dhdb = dhdb;
                     pstate = PSServer(ClientHello(cvd,svd))
                    })
        | _ -> (* Handshake already ongoing, ignore this request *)
            (false,state))

let getPrincipal ci state =
  match ci.role with
    | Client -> state.poptions.server_name
    | Server -> state.poptions.client_name

let invalidateSession ci state =
    let i = isInitEpoch(ci.id_in) in
    if i = true then
        state
    else
        let si = epochSI(ci.id_in) in
        match si.sessionID with
        | xx when length xx = 0 -> state
        | sid ->
            let hint = getPrincipal ci state in
            let sdb = SessionDB.remove state.sDB sid ci.role hint in
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
    | xx when length xx = 0 ->
        (match state.pstate with
        | PSClient(cstate) ->
            (match cstate with
            | ClientWritingCCS (si,ms,log) ->
                (let cr' = si.init_crand in
                let sr' = si.init_srand in
                Pi.assume (SentCCS(Client,cr',sr',si)); // ``We send client CCS for si''
                let next_ci = getNextEpochs ci si cr' sr' in
                let nki_in = id next_ci.id_in in
                let nki_out = id next_ci.id_out in
                let (reader,writer) = PRF.keyGenClient nki_in nki_out ms in

                let cvd = PRF.makeVerifyData si ms Client log in
                let cFinished = messageBytes HT_finished cvd in
                let log = log @| cFinished in
                let ki_out = ci.id_out in
                let (rg,f,_) = makeFragment ki_out CCSBytes in
                let ci = {ci with id_out = next_ci.id_out} in
                OutCCS(rg,f,ci,writer,
                       {state with hs_outgoing = cFinished;
                                   pstate = PSClient(ServerCCS(si,ms,next_ci.id_in,reader,cvd,log))}))

            | ClientWritingCCSResume(e,w,ms,svd,log) ->
                (let cr' = epochCRand(e) in
                let sr' = epochSRand(e) in
                let si' = epochSI(e) in
                Pi.assume (SentCCS(Client,cr',sr',si')); // ``We send client CCS for the resumption''
                let cvd = PRF.makeVerifyData si' ms Client log in
                let cFinished = messageBytes HT_finished cvd in
                let ki_out = ci.id_out in
                let (rg,f,_) = makeFragment ki_out CCSBytes in
                let ci = {ci with id_out = e} in
#if verify
                Pi.expect (Complete(ci));
#endif
                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = cFinished;
                                   pstate = PSClient(ClientWritingFinishedResume(cvd,svd))}))
            | _ -> OutIdle(state))
        | PSServer(sstate) ->
            (match sstate with
            | ServerWritingCCS (si,ms,e,w,cvd,log) ->
                (Pi.assume (SentCCS(Server,si.init_crand,si.init_srand,si)); // ``We send server CCS for si''
                let svd = PRF.makeVerifyData si ms Server log in
                let sFinished = messageBytes HT_finished svd in
                let ki_out = ci.id_out in
                let (rg,f,_) = makeFragment ki_out CCSBytes in
                let ci = {ci with id_out = e} in
#if verify
                Pi.expect(Complete(ci));
#endif
                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = sFinished;
                                   pstate = PSServer(ServerWritingFinished(si,ms,e,cvd,svd))}))
            | ServerWritingCCSResume(we,w,re,r,ms,log) ->
                (let si' = epochSI(we) in
                let cr' = epochCRand(we) in
                let sr' = epochSRand(we) in
                Pi.assume (SentCCS(Server,cr',sr',si')); // ``We send server CCS for the resumption''
                let svd = PRF.makeVerifyData si' ms Server log in
                let sFinished = messageBytes HT_finished svd in
                let log = log @| sFinished in
                let ki_out = ci.id_out in
                let (rg,f,_) = makeFragment ki_out CCSBytes in
                let ci = {ci with id_out = we} in
                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = sFinished;
                                   pstate = PSServer(ClientCCSResume(re,r,svd,ms,log))}))

            | _ -> OutIdle(state)))
    | outBuf ->
        let ki_out = ci.id_out in
        let (rg,f,remBuf) = makeFragment ki_out outBuf in
        (match remBuf with
        | xx when length xx = 0 ->
            (match state.pstate with
            | PSClient(cstate) ->
                (match cstate with
                | ServerCCS (_,_,_,_,_,_) ->
                    (
#if verify
                    Pi.assume(EvSentFinishedFirst(ci,true));
#endif
                    OutFinished(rg,f,{state with hs_outgoing = remBuf}))
                | ClientWritingFinishedResume(cvd,svd) ->
                    (let si = epochSI ki_out in
                    let op = state.poptions in
                    check_negotiation Client si op;
#if verify
                    Pi.assume(EvSentFinishedFirst(ci,false));
#endif
                    OutComplete(rg,f,
                                {state with hs_outgoing = remBuf;
                                            pstate = PSClient(ClientIdle(cvd,svd))}))

                | _ -> OutSome(rg,f,{state with hs_outgoing = remBuf}))
            | PSServer(sstate) ->
                (match sstate with
                | ServerWritingFinished(si,ms,e,cvd,svd) ->
                    (
#if verify
                    Pi.assume(EvSentFinishedFirst(ci,false));
#endif
                    if length si.sessionID = 0 then
                      (check_negotiation Server si state.poptions;
                      OutComplete(rg,f,
                                  {state with hs_outgoing = remBuf;
                                              pstate = PSServer(ServerIdle(cvd,svd))}))

                    else
                      (let sdb = SessionDB.insert state.sDB si.sessionID Server state.poptions.client_name (si,ms) in
                      check_negotiation Server si state.poptions;
                      OutComplete(rg,f,
                                  {state with hs_outgoing = remBuf;
                                              pstate = PSServer(ServerIdle(cvd,svd));
                                              sDB = sdb})))

                | ClientCCSResume(_,_,_,_,_) ->
                    (
#if verify
                    Pi.assume(EvSentFinishedFirst(ci,true));
#endif
                    OutFinished(rg,f,{state with hs_outgoing = remBuf}))
                | _ -> OutSome(rg,f,{state with hs_outgoing = remBuf})))
        | _ -> OutSome(rg,f,{state with hs_outgoing = remBuf}))

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
let find_client_cert_sign certType certAlg (distName:list<string>) pv hint =
    match pv with
    | TLS_1p2 ->
        let keyAlg = sigHashAlg_bySigList certAlg (cert_type_list_to_SigAlg certType) in
        Cert.for_signing certAlg hint keyAlg
    | TLS_1p1 | TLS_1p0 | SSL_3p0 ->
        let certAlg = cert_type_list_to_SigHashAlg certType pv in
        let keyAlg = sigHashAlg_bySigList certAlg (cert_type_list_to_SigAlg certType) in
        Cert.for_signing certAlg hint keyAlg

(*
let getCertificateBytes (si:SessionInfo) (cert_req:option<(Cert.chain * Sig.alg * Sig.skey)>) =
  let clientCertBytes = clientCertificateBytes cert_req in
  match cert_req with
    | None when si.client_auth = true -> clientCertBytes,[]
    | Some x when si.client_auth = true ->
        let (certList,_,_) = x in clientCertBytes,certList
    | _ when si.client_auth = false -> empty_bytes,[]

let getCertificateVerifyBytes (si:SessionInfo) (ms:PRF.masterSecret) (cert_req:option<(Cert.chain * Sig.alg * Sig.skey)>) (l:log) =
  match cert_req with
    | None when si.client_auth = true ->
        (* We sent an empty Certificate message, so no certificate verify message at all *)
        empty_bytes
    | Some(x) when si.client_auth = true ->
        let (certList,algs,skey) = x in
          let (mex,_) = makeCertificateVerifyBytes si ms algs skey l in
          mex
    | _ when si.client_auth = false ->
        (* No client certificate ==> no certificateVerify message *)
        empty_bytes
*)

let extract si pms (log:bytes) =
        si, KEF.extract si pms

let clientKEXBytes_RSA si config =
    if List.listLength si.serverID = 0 then
        unexpected "[clientKEXBytes_RSA] Server certificate should always be present with a RSA signing cipher suite."
    else
        match Cert.get_chain_public_encryption_key si.serverID with
        | Error(z) -> Error(z)
        | Correct(pubKey) ->

            let pms = PMS.genRSA pubKey config.maxVer in
            let encpms = RSA.encrypt pubKey config.maxVer pms in
            let mex = clientKeyExchangeBytes_RSA si encpms in
            correct(pubKey,mex,pms)

let parseClientKEX_RSA si skey cv config data =
    if List.listLength si.serverID = 0 then
        unexpected "[parseClientKEX_RSA] when the ciphersuite can encrypt the PMS, the server certificate should always be set"
    else
        match Cert.get_chain_public_encryption_key si.serverID with
        | Correct(pk) ->
            (match parseClientKeyExchange_RSA si data with
            | Correct(encPMS) ->

                let res = RSA.decrypt skey si cv config.check_client_version_in_pms_for_old_tls encPMS in
                correct(pk,(*RSAPMS(pk,cv,encPMS),*)res)
            | Error(z) -> Error(z))
        | Error(x) -> Error(x)

let prepare_client_output_full_RSA (ci:ConnectionInfo) (state:hs_state) (si:SessionInfo) (cert_req:Cert.sign_cert) (log:log) : Result<(hs_state * SessionInfo * PRF.masterSecret * log)> =
    match cert_req with
    | _ when si.client_auth = false ->
         let si = {si with clientID = []} in
         let cfg = state.poptions in
         (match clientKEXBytes_RSA si cfg with
         | Error(z) -> Error(z)
         | Correct(v) ->
           let (pk,clientKEXBytes,rsapms)  = v in
           let cv = cfg.maxVer in

           let pms = PMS.RSAPMS(pk,cv,rsapms) in
           let pmsid = pmsId pms in
           let log = log @| clientKEXBytes in
           (* Enqueue current messages in output buffer *)
           let to_send = clientKEXBytes in
           let new_outgoing = state.hs_outgoing @| to_send in
           let si = {si with pmsId = pmsid} in
           let (si,ms) = extract si pms log in
#if verify
           Pi.expect (ClientLogBeforeClientFinishedRSA_NoAuth(si,log));
#endif
           correct ({state with hs_outgoing = new_outgoing},si,ms,log))
    | None when si.client_auth = true ->
         let clientCertBytes = clientCertificateBytes cert_req in
         let si_old = si in
         let si = {si with clientID = []} in
         let log = log @| clientCertBytes in
         let cfg = state.poptions in
         (match clientKEXBytes_RSA si cfg with
         | Error(z) -> Error(z)
         | Correct(v) ->
           let (pk,clientKEXBytes,rsapms)  = v in
           let cv = cfg.maxVer in

           let pms = PMS.RSAPMS(pk,cv,rsapms) in
           let pmsid = pmsId pms in
           let si = {si with pmsId = pmsid} in
           let log = log @| clientKEXBytes in
           (* Enqueue current messages in output buffer *)
           let to_send = clientCertBytes @| clientKEXBytes in
           let new_outgoing = state.hs_outgoing @| to_send in
           let (si,ms) = extract si pms log in
#if verify
           Pi.expect (UpdatesPmsClientID(si_old,si));
           Pi.expect (ClientLogBeforeClientFinishedRSA_TryNoAuth(si,log));
#endif
           correct ({state with hs_outgoing = new_outgoing},si,ms,log))
    | Some x when si.client_auth = true ->
         let si_old = si in
         let (certList,algs,skey) = x in
         let clientCertBytes = clientCertificateBytes cert_req in
         let si = {si with clientID = certList} in
         let si = {si with clientSigAlg = algs} in
         let log = log @| clientCertBytes in
         let cfg = state.poptions in
         (match clientKEXBytes_RSA si cfg with
         | Error(z) -> Error(z)
         | Correct(v) ->
           let (pk,clientKEXBytes,rsapms)  = v in
           let cv = cfg.maxVer in

           let pms = PMS.RSAPMS(pk,cv,rsapms) in
           let pmsid = pmsId pms in
           let si = {si with pmsId = pmsid} in
           let log = log @| clientKEXBytes in
           let (si,ms) = extract si pms log in

#if verify

           Pi.expect (UpdatesPmsClientID(si_old,si));
           Pi.expect (ClientLogBeforeCertificateVerifyRSA_Auth(si,log));
#endif

           let (certificateVerifyBytes,_) = makeCertificateVerifyBytes si ms algs skey log in
           let log = log @| certificateVerifyBytes in

           (* Enqueue current messages in output buffer *)
           let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
           let new_outgoing = state.hs_outgoing @| to_send in
#if verify
           Pi.expect (UpdatesPmsClientID(si_old,si));
           Pi.expect (ClientLogBeforeClientFinishedRSA_Auth(si,log));
#endif
           correct ({state with hs_outgoing = new_outgoing},si,ms,log))
    | _ -> Error.unexpected "[prepare_client_output_full_RSA] unreachable pattern match"

(*
let sessionInfoCertBytesAuth (si:SessionInfo) (cert_req:Cert.sign_cert)=
  if si.client_auth then
    let cb = clientCertificateBytes cert_req in
    match cert_req with
     | None -> (si,cb)
     | Some(x) ->
         let (certList,_,_) = x in
         ({si with clientID = certList},cb)
  else (si,empty_bytes)

*)

(*
let certificateVerifyBytesAuth (si:SessionInfo) (ms:PRF.masterSecret) (cert_req:Cert.sign_cert) (log:bytes) =
        if si.client_auth then
            match cert_req with
            | None ->
                (* We sent an empty Certificate message, so no certificate verify message at all *)
                empty_bytes
            | Some(x) ->
                let (certList,algs,skey) = x in
                let (mex,_) = makeCertificateVerifyBytes si ms algs skey log in
                mex
        else
            (* No client certificate ==> no certificateVerify message *)
            empty_bytes
*)

let prepare_client_output_full_DHE (ci:ConnectionInfo) (state:hs_state) (si:SessionInfo)
  (cert_req:Cert.sign_cert) (dhp:dhparams) (sy:DHGroup.elt) (log:log) : Result<(hs_state * SessionInfo * PRF.masterSecret * log)> =
    (* pre: Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> DHGroup.PP(dhp) /\ ServerDHE(dhp,sy,si.init_crand @| si.init_srand) *)
    (* moreover, by definition ServerDHE(dhp,sy,si.init_crand @| si.init_srand) implies ?sx.DHE.Exp(dhp,sx,sy) *)

    match cert_req with
    | Some x when si.client_auth = true ->
         let si_old = si in
         let (certList,algs,skey) = x in
         let clientCertBytes = clientCertificateBytes cert_req in
         let si = {si with clientID = certList} in
         let si = {si with clientSigAlg = algs} in
         let log = log @| clientCertBytes in
         let cfg = state.poptions in

         (* this implements ms-KEM(DH).enc with pk = (dhp,sy) and (pv,h,l) from si *)

         let (cy,dhpms) = DH.clientGenExp dhp sy in
         (* post: DHE.Exp(dhp,x,cy) *)

         let clientKEXBytes = clientKEXExplicitBytes_DH cy in
         let log = log @| clientKEXBytes in

         let pms = PMS.DHPMS(dhp.dhp,dhp.dhg,sy,cy,dhpms) in
         let pmsid = pmsId pms in
         let si = {si with pmsId = pmsid} in
         let (si,ms) = extract si pms log in

         (* the post of this call is !sx,cy. PP(dhp) /\ DHE.Exp(dhp,cx,cy)) /\ DHE.Exp(dhp,sx,sy) -> DH.HonestExponential(dhp,cy,sy) *)
         (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> DH.HonestExponential(dhp,cy,sy) *)
         (* the post of this call is !dhp,gx,gy. StrongHS(si) /\ DH.HonestExponential(dhp,gx,gy) -> PRFs.Secret(ms) *)
         (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> PRFs.Secret(ms) *)
         (* si is now constant *)

#if verify

         Pi.expect (UpdatesPmsClientID(si_old,si));
         Pi.expect (ClientLogBeforeCertificateVerifyDHE_Auth(si,log));
#endif

         let (certificateVerifyBytes,_) = makeCertificateVerifyBytes si ms algs skey log in

         let log = log @| certificateVerifyBytes in

         let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
         let new_outgoing = state.hs_outgoing @| to_send in
#if verify
         Pi.expect (UpdatesPmsClientID(si_old,si));
         Pi.expect (ClientLogBeforeClientFinishedDHE_Auth(si,log));
#endif
         correct ({state with hs_outgoing = new_outgoing},si,ms,log)
    | None when si.client_auth = true ->
         let si_old = si in
         let clientCertBytes = clientCertificateBytes cert_req in
         let si = {si with clientID = []} in
         let log = log @| clientCertBytes in
         let cfg = state.poptions in

         (* this implements ms-KEM(DH).enc with pk = (dhp,sy) and (pv,h,l) from si *)

         let (cy,dhpms) = DH.clientGenExp dhp sy in
         (* post: DHE.Exp(dhp,x,cy) *)

         let clientKEXBytes = clientKEXExplicitBytes_DH cy in
         let log = log @| clientKEXBytes in

         let pms = PMS.DHPMS(dhp.dhp,dhp.dhg,sy,cy,dhpms) in
         let pmsid = pmsId pms in
         let si = {si with pmsId = pmsid} in
         let (si,ms) = extract si pms log in

         (* the post of this call is !sx,cy. PP(dhp) /\ DHE.Exp(dhp,cx,cy)) /\ DHE.Exp(dhp,sx,sy) -> DH.HonestExponential(dhp,cy,sy) *)
         (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> DH.HonestExponential(dhp,cy,sy) *)
         (* the post of this call is !dhp,gx,gy. StrongHS(si) /\ DH.HonestExponential(dhp,gx,gy) -> PRFs.Secret(ms) *)
         (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> PRFs.Secret(ms) *)
         (* si is now constant *)

         let to_send = clientCertBytes @| clientKEXBytes in
         let new_outgoing = state.hs_outgoing @| to_send in
#if verify
         Pi.expect (UpdatesPmsClientID(si_old,si));
         Pi.expect (ClientLogBeforeClientFinishedDHE_TryNoAuth(si,log));
#endif
         correct ({state with hs_outgoing = new_outgoing},si,ms,log)
    | _ when si.client_auth = false ->
         let si_old = si in
         let si = {si with clientID = []} in
         let cfg = state.poptions in

         (* this implements ms-KEM(DH).enc with pk = (dhp,sy) and (pv,h,l) from si *)

         let (cy,dhpms) = DH.clientGenExp dhp sy in
         (* post: DHE.Exp(dhp,x,cy) *)

         let clientKEXBytes = clientKEXExplicitBytes_DH cy in
         let log = log @| clientKEXBytes in

         let pms = PMS.DHPMS(dhp.dhp,dhp.dhg,sy,cy,dhpms) in
         let pmsid = pmsId pms in
         let si = {si with pmsId = pmsid} in
         let (si,ms) = extract si pms log in

         (* the post of this call is !sx,cy. PP(dhp) /\ DHE.Exp(dhp,cx,cy)) /\ DHE.Exp(dhp,sx,sy) -> DH.HonestExponential(dhp,cy,sy) *)
         (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> DH.HonestExponential(dhp,cy,sy) *)
         (* the post of this call is !dhp,gx,gy. StrongHS(si) /\ DH.HonestExponential(dhp,gx,gy) -> PRFs.Secret(ms) *)
         (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> PRFs.Secret(ms) *)
         (* si is now constant *)

         let to_send = clientKEXBytes in
         let new_outgoing = state.hs_outgoing @| to_send in
#if verify
         Pi.expect (UpdatesPmsClientID(si_old,si));
         Pi.expect (ClientLogBeforeClientFinishedDHE_NoAuth(si,log));
#endif
         correct ({state with hs_outgoing = new_outgoing},si,ms,log)
    | _ -> Error.unexpected "[prepare_client_output_full_DHE] unreachable pattern match"

let on_serverHello_full (ci:ConnectionInfo) crand log to_log (shello:ProtocolVersion * srand * sessionID * cipherSuite * Compression * bytes) extL =
    let log = log @| to_log in
    let (sh_server_version,sh_random,sh_session_id,sh_cipher_suite,sh_compression_method,sh_neg_extensions) = shello in
    let si = { clientID = [];
               clientSigAlg = (SA_RSA,SHA);
               serverSigAlg = (SA_RSA,SHA);
               client_auth = false;
               serverID = [];
               sessionID = sh_session_id;
               protocol_version = sh_server_version;
               cipher_suite = sh_cipher_suite;
               compression = sh_compression_method;
               extensions = extL;
               init_crand = crand;
               init_srand = sh_random;
               session_hash = empty_bytes;
               pmsId = noPmsId
               } in
    (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
    if isAnonCipherSuite sh_cipher_suite then
        PSClient(ServerKeyExchangeDH_anon(si,log))
    else if isDHCipherSuite sh_cipher_suite then
        PSClient(ServerCertificateDH(si,log))
    else if isDHECipherSuite sh_cipher_suite then
        PSClient(ServerCertificateDHE(si,log))
    else if isRSACipherSuite sh_cipher_suite then
        PSClient(ServerCertificateRSA(si,log))
    else
        unexpected "[on_serverHello_full] Unknown ciphersuite"

let parseMessageState (ci:ConnectionInfo) state =
    match parseMessage state.hs_incoming with
    | Error(z) -> Error(z)
    | Correct(res) ->
        match res with
        | None -> correct(None)
        | Some(x) ->
             let (rem,hstype,payload,to_log) = x in
             let state = { state with hs_incoming = rem } in
             let nx = (state,hstype,payload,to_log) in
             let res = Some(nx) in
             correct(res)

let rec recv_fragment_client (ci:ConnectionInfo) (state:hs_state) (agreedVersion:option<ProtocolVersion>) =
    match parseMessageState ci state with
    | Error z -> let (x,y) = z in InError(x,y,state)
    | Correct(res) ->
      (match res with
      | None ->
          (match agreedVersion with
          | None      -> InAck(state)
          | Some (pv) -> InVersionAgreed(state,pv))
      | Some (res) ->
      let (state,hstype,payload,to_log) = res in
      (match state.pstate with
      | PSClient(cState) ->
        (match hstype with
        | HT_hello_request ->
            (match cState with
            | ClientIdle(_,_) ->
                (* This is a legitimate hello request.
                   Handle it, but according to the spec do not log this message *)
                (match state.poptions.honourHelloReq with
                | HRPIgnore -> recv_fragment_client ci state agreedVersion
                | HRPResume -> let (_,state) = rekey ci state state.poptions in InAck(state)        (* Terminating case, we're not idle anymore *)
                | HRPFull   -> let (_,state) = rehandshake ci state state.poptions in InAck(state)) (* Terminating case, we're not idle anymore *)
            | _ ->
                (* RFC 7.4.1.1: ignore this message *)
                recv_fragment_client ci state agreedVersion)

        | HT_server_hello ->
            (match cState with
            | ServerHello (crand,sid,cExtL,cvd,svd,log) ->
                (match parseServerHello payload with
                | Error z -> let (x,y) = z in InError(x,y,state)
                | Correct (shello) ->
                  let (sh_server_version,sh_random,sh_session_id,sh_cipher_suite,sh_compression_method,sh_neg_extensions) = shello in
                  let pop = state.poptions in
                  // Sanity checks on the received message; they are security relevant.
                  // Check that the server agreed version is between maxVer and minVer.
                  if  (geqPV sh_server_version pop.minVer
                       && geqPV pop.maxVer sh_server_version) = false
                  then
                    InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation",state)
                  else
                  // Check that the negotiated ciphersuite is in the proposed list.
                  // Note: if resuming a session, we still have to check that this ciphersuite is the expected one!
                  if  (List.memr state.poptions.ciphersuites sh_cipher_suite) = false
                  then
                    InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation",state)
                  else
                  // Check that the compression method is in the proposed list.
                  if (List.memr state.poptions.compressions sh_compression_method) = false
                  then
                    InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation",state)
                  else
                  // Parse extensions
                  (match parseServerExtensions sh_neg_extensions with
                  | Error z ->
                      let (x,y) = z in
                      InError(x,y,state)
                  | Correct(sExtL) ->
                  // Handling of safe renegotiation //#begin-safe_renego
                  if checkServerRenegotiationInfoExtension state.poptions sExtL cvd svd then
                    //#end-safe_renego
                    // Log the received message.
                    (* Check whether we asked for resumption *)
                    if (length sid > 0) && (equalBytes sid sh_session_id) then
                        (* use resumption *)
                        (* Search for the session in our DB *)
                        let sess = SessionDB.select state.sDB sid Client state.poptions.server_name in
                        (match sess with
                        | None ->
                            (* This can happen, although we checked for the session before starting the HS.
                                For example, the session may have expired between us sending client hello, and now. *)
                            InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "A session expried while it was being resumed",state)
                        | Some(storable) ->
                        let (si,ms) = storable in
                        let log = log @| to_log in
                        (* Check that protocol version, ciphersuite and compression method are indeed the correct ones *)
                        (* We know statically that this session supports extended master secret, because we never ask to
                           resume sessions for which the extension was not negotiated *)

                          if si.protocol_version = sh_server_version then
                            if si.cipher_suite = sh_cipher_suite then
                                if si.compression = sh_compression_method then
                                    let next_ci = getNextEpochs ci si crand sh_random in
                                    let nki_in = id next_ci.id_in in
                                    let nki_out = id next_ci.id_out in
                                    let (reader,writer) = PRF.keyGenClient nki_in nki_out ms in
                                    let nout = next_ci.id_out in
                                    let nin = next_ci.id_in in

                                    Pi.expect (Authorize(Client,si)); // annotation
                                    recv_fragment_client ci
                                        {state with pstate = PSClient(ServerCCSResume(nout,writer,
                                                                                    nin,reader,
                                                                                    ms,log))}
                                        (somePV sh_server_version)
                                else
                                    InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation",state)
                            else

                                InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation",state)
                          else
                              InError(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation",state))

                    else
                        (* we did not request resumption, or the server didn't accept it: do a full handshake *)
                        (* define the sinfo we're going to establish *)
                        (match negotiateClientExtensions cExtL sExtL false (* Not resuming *) sh_cipher_suite with
                        | Error(z) -> let (x,y) = z in InError(x,y,state)
                        | Correct(nExtL) ->
                            let next_pstate = on_serverHello_full ci crand log to_log shello nExtL in
                            recv_fragment_client ci {state with pstate = next_pstate} (somePV sh_server_version))
                  else
                    InError (AD_handshake_failure,perror __SOURCE_FILE__ __LINE__ "Wrong renegotiation information provided",state)))

            | _ ->
                InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerHello arrived in the wrong state",state))
        | HT_certificate ->
            (match cState with
            // Most of the code in the branches is duplicated, but it helps for verification
            | ServerCertificateRSA (si,log) ->
                (match parseClientOrServerCertificate payload with
                | Error z ->
                    let (x,y) = z in
                    InError(x,y,state)
                | Correct([]) ->
                    InError(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Server sent empty certificate",state)
                | Correct(certs) ->
                    let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, this is the same as we sent in our extension
                    if Cert.is_chain_for_key_encryption certs then
                        let advice = Cert.validate_cert_chain allowedAlgs certs in
                        (match Cert.get_hint certs with
                        | None ->
                          InQuery(certs,false,{state with pstate = PSClient(ClientCheckingCertificateRSA(si,log,certs,agreedVersion,to_log))})
                        | Some(name) ->
                          if (name = state.poptions.server_name) then
                              InQuery(certs,advice,{state with pstate = PSClient(ClientCheckingCertificateRSA(si,log,certs,agreedVersion,to_log))})
                          else
                              InQuery(certs,false,{state with pstate = PSClient(ClientCheckingCertificateRSA(si,log,certs,agreedVersion,to_log))}))
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Server sent wrong certificate type",state))
            | ServerCertificateDHE (si,log) ->
                (match parseClientOrServerCertificate payload with
                | Error z ->
                    let (x,y) = z in
                    InError(x,y,state)
                | Correct([]) ->
                    InError(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Server sent empty certificate",state)
                | Correct(certs) ->
                    let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, this is the same as we sent in our extension
                    if Cert.is_chain_for_signing certs then
                        let advice = Cert.validate_cert_chain allowedAlgs certs in
                        (match Cert.get_hint certs with
                        | None -> InQuery(certs,false,{state with pstate = PSClient(ClientCheckingCertificateDHE(si,log,certs,agreedVersion,to_log))})
                        | Some(name) -> let advice = advice && (name = state.poptions.server_name) in
                                        InQuery(certs,advice,{state with pstate = PSClient(ClientCheckingCertificateDHE(si,log,certs,agreedVersion,to_log))}))
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Server sent wrong certificate type",state))
            | ServerCertificateDH (si,log) ->
                InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented",state)
            | _ ->
                InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Certificate arrived in the wrong state",state))

        | HT_server_key_exchange ->
            (match cState with
            | ServerKeyExchangeDHE(si,log) ->
                let ops = state.poptions in
                let dhstrength = ops.dhPQMinLength in
                (match parseServerKeyExchange_DHE state.dhdb dhstrength si.protocol_version si.cipher_suite payload with
                | Error z ->
                    let (x,y) = z in
                    InError(x,y,state)
                | Correct(v) ->
                    let (dhdb,dhp,y,alg,signature) = v in
                    let state = {state with dhdb = dhdb} in
                    let vk = Cert.get_chain_public_signing_key si.serverID alg in
                    match vk with
                    | Error z ->
                        let (x,y) = z in
                        InError(x,y,state)
                    | Correct(vkey) ->
                        let dheb = dheParamBytes dhp.dhp dhp.dhg y in
                        let expected = si.init_crand @| si.init_srand @| dheb in
                        if Sig.verify alg vkey expected signature then
                            (let si_old = si in
                            let si = {si with serverSigAlg = alg} in
                            let log = log @| to_log in
#if verify
                            Pi.expect(UpdatesServerSigAlg(si_old,si));
#endif
                            recv_fragment_client ci
                              {state with pstate = PSClient(CertificateRequestDHE(si,dhp,y,log))}
                              agreedVersion)
                        else
                            InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "",state))

            | ServerKeyExchangeDH_anon(si,log) ->
                let ops = state.poptions in
                let dhstrength = ops.dhPQMinLength in
                (match parseServerKeyExchange_DH_anon state.dhdb dhstrength payload with
                | Error z -> let (x,y) = z in InError(x,y,state)
                | Correct(v) ->
                    let (dhdb,dhp,y) = v in
                    let log = log @| to_log in
                    let state = {state with dhdb = dhdb} in
                    recv_fragment_client ci
                      {state with pstate = PSClient(ServerHelloDoneDH_anon(si,dhp,y,log))}
                      agreedVersion)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerKeyExchange arrived in the wrong state",state))

        | HT_certificate_request ->
            (match cState with
            | CertificateRequestRSA(si,log) ->
                (* Log the received packet *)
                let log = log @| to_log in

                (* Note: in next statement, use si, because the handshake runs according to the session we want to
                   establish, not the current one *)
                (match parseCertificateRequest si.protocol_version payload with
                | Error z -> let (x,y) = z in  InError(x,y,state)
                | Correct(v) ->
                    let (certType,alg,distNames) = v in
                    let client_cert = find_client_cert_sign certType alg distNames si.protocol_version state.poptions.client_name in
                    let si' = {si with client_auth = true} in

#if verify
                    Pi.expect (UpdatesClientAuth(si,si'));
#endif
                    recv_fragment_client ci
                      {state with pstate = PSClient(ServerHelloDoneRSA(si',client_cert,log))}
                      agreedVersion)
            | CertificateRequestDHE(si,dhp,y,log) ->
                // Duplicated code
                (* Log the received packet *)
                let log = log @| to_log in

                (* Note: in next statement, use si, because the handshake runs according to the session we want to
                   establish, not the current one *)
                (match parseCertificateRequest si.protocol_version payload with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct(v) ->
                    let (certType,algs,distNames) = v in
                    let client_cert = find_client_cert_sign certType algs distNames si.protocol_version state.poptions.client_name in
                    let si' = {si with client_auth = true} in

#if verify
                    Pi.expect (UpdatesClientAuth(si,si'));
#endif
                    recv_fragment_client ci
                      {state with pstate = PSClient(ServerHelloDoneDHE(si',client_cert,dhp,y,log))}
                      agreedVersion)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CertificateRequest arrived in the wrong state",state))

        | HT_server_hello_done ->
            (match cState with
            | CertificateRequestRSA(si,log) ->
                let pl = length payload in
                if pl = 0 then
                    (* Log the received packet *)
                    let log' = log @| to_log in
                    let si' = {si with client_auth = false} in

                    (* Should be provable *)
#if verify
                    Pi.expect (UpdatesClientAuth(si,si'));
                    Pi.expect (Authorize(Client,si'));
                    Pi.expect (ClientLogBeforeServerHelloDoneRSA_NoAuth(si',log));
                    Pi.expect (ClientLogAfterServerHelloDoneRSA(si',log'));
#endif
                    let log = log' in
                    let prep = prepare_client_output_full_RSA ci state si' None log in
                    match prep with
                    | Error z ->
                        let (x,y) = z in
                        InError (x,y, state)
                    | Correct z ->
                        let (state,si,ms,log) = z in
                        recv_fragment_client ci
                          {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                          agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | ServerHelloDoneRSA(si,skey,log) ->
                if length payload = 0 then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_RSA ci state si skey log with
                    | Error z ->
                        let (x,y) = z in
                        InError (x,y, state)
                    | Correct z ->
                        let (state,si,ms,log) = z in
                        recv_fragment_client ci
                          {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                          agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
#if verify
#else
            | ServerHelloDoneDH_anon(si,dhp,y,log)

#endif
            | CertificateRequestDHE(si,dhp,y,log) ->
                if length payload = 0 then
                    (* Log the received packet *)
                    let log' = log @| to_log in
                    let si' = {si with client_auth = false} in
                    (* Should be provable *)
#if verify
                    Pi.expect (UpdatesClientAuth(si,si'));
                    Pi.expect (Authorize(Client,si'));
                    Pi.expect (ClientLogBeforeServerHelloDoneDHE_NoAuth(si',log));
                    Pi.expect (ClientLogAfterServerHelloDoneDHE(si',log'));
#endif
                    let log = log' in
                    let dhe = prepare_client_output_full_DHE ci state si' None dhp y log in
                    match dhe with
                    | Error z ->
                        let (x,y) = z in
                        InError (x,y, state)
                    | Correct z ->
                        let (state,si,ms,log) = z in
                        recv_fragment_client ci
                          {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                          agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | ServerHelloDoneDHE(si,skey,dhp,y,log) ->
                if length  payload = 0 then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_DHE ci state si skey dhp y log with
                    | Error z ->
                        let (x,y) = z in
                        InError (x,y, state)
                    | Correct z ->
                        let (state,si,ms,log) = z in
                        recv_fragment_client ci
                          {state with pstate = PSClient(ClientWritingCCS(si,ms,log))}
                          agreedVersion
                else
                    InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerHelloDone arrived in the wrong state",state))

        | HT_finished ->
            (match cState with
            | ServerFinished(si,ms,e,cvd,log) ->
                if PRF.checkVerifyData si ms Server log payload then
                    (let sDB =
                        if length si.sessionID = 0 then state.sDB
                        else SessionDB.insert state.sDB si.sessionID Client state.poptions.server_name (si,ms)
                    in
                    (* Should prove from checkVerifyData above *)
#if verify
                    Pi.expect (Complete(ci));
#endif
                    check_negotiation Client si state.poptions;
                    InComplete({state with pstate = PSClient(ClientIdle(cvd,payload)); sDB = sDB}))
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | ServerFinishedResume(e,w,ms,log) ->
                let si = epochSI ci.id_in in
                let check = PRF.checkVerifyData si ms Server log payload in
                if check then
                    let log = log @| to_log in
#if verify
                    Pi.expect(LClientFinishedResume(e,log));
#endif
                    InFinished({state with pstate = PSClient(ClientWritingCCSResume(e,w,ms,payload,log))})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Finished arrived in the wrong state",state))
        | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Unrecognized message",state))

      (* Should never happen *)
      | PSServer(_) -> unexpected "[recv_fragment_client] should only be invoked when in client role."))

let prepare_server_output_full_RSA (ci:ConnectionInfo) state si cv calgs sExtL log =
    let ext = serverExtensionsBytes sExtL in
    let serverHelloB = serverHelloBytes si si.init_srand ext in
    match Cert.for_key_encryption calgs state.poptions.server_name with
    | None -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Could not find in the store a certificate for the negotiated ciphersuite")
    | Some(x) ->
        let (c,sk) = x in
        (* update server identity in the sinfo *)
        let si = {si with serverID = c} in
        let certificateB = serverCertificateBytes c in
        (* No ServerKeyExchange in RSA ciphersuites *)
        (* Compute the next state of the server *)
        if si.client_auth then
          let certificateRequestB = certificateRequestBytes true si.cipher_suite si.protocol_version in // true: Ask for sign-capable certificates
          let output = serverHelloB @| certificateB @| certificateRequestB @| serverHelloDoneBytes in
          (* Log the output and put it into the output buffer *)
          let log = log @| output in
          let ps = serverState ci (ClientCertificateRSA(si,cv,sk,log)) in
          correct ({state with hs_outgoing = output;
                               pstate = ps},
                    si.protocol_version)
        else
          let output = serverHelloB @| certificateB @| serverHelloDoneBytes in
          (* Log the output and put it into the output buffer *)
          let log = log @| output in
#if verify
          Pi.expect (ServerLogBeforeClientCertificateRSA_NoAuth(si,cv,log));
#endif
          let ps = serverState ci (ClientKeyExchangeRSA(si,cv,sk,log)) in
          correct ({state with hs_outgoing = output;
                               pstate = ps},
                    si.protocol_version)

let prepare_server_output_full_DH ci state si sExtL log: Result<'f> =
#if verify
  failwith "not implemented fixed DH"
#else
  Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented")
#endif

let prepare_server_output_full_DHE (ci:ConnectionInfo) state si certAlgs sExtL log =
    let ext = serverExtensionsBytes sExtL in
    let serverHelloB = serverHelloBytes si si.init_srand ext in
    let keyAlgs = sigHashAlg_bySigList certAlgs [sigAlg_of_ciphersuite si.cipher_suite] in
    if List.listLength keyAlgs = 0 then
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "The client provided inconsistent signature algorithms and ciphersuites")
    else
    let cer = Cert.for_signing certAlgs state.poptions.server_name keyAlgs in
    match cer with
    | None -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Could not find in the store a certificate for the negotiated ciphersuite")
    | Some(creq) ->
        let (c,alg,sk) = creq in
        (* set server identity in the session info *)
        let si = {si with serverID = c} in
        let si = {si with serverSigAlg = alg} in
        let certificateB = serverCertificateBytes c in

        (* ServerKeyExchange *)

        let dhparams_filename = state.poptions.dhDefaultGroupFileName in
        let ops = state.poptions in
        let dhstrength = ops.dhPQMinLength in
        let (dhdb,dhp,gx,x) = DH.serverGen dhparams_filename state.dhdb dhstrength  in
        //~ pms-KEM: (dhp,gx),((dhp,gx),x) = keygen_DHE()
        let state = {state with dhdb = dhdb} in

        let dheB = dheParamBytes dhp.dhp dhp.dhg gx in
        let toSign = si.init_crand @| si.init_srand @| dheB in
        let sign = Sig.sign alg sk toSign in

        let serverKEXB = serverKeyExchangeBytes_DHE dheB alg sign si.protocol_version in

        (* CertificateRequest *)
        if si.client_auth then
          let certificateRequestB = certificateRequestBytes true si.cipher_suite si.protocol_version in // true: Ask for sign-capable certificates
          let output = serverHelloB @| certificateB @| serverKEXB @| certificateRequestB @| serverHelloDoneBytes in
          (* Log the output and put it into the output buffer *)
          let log = log @| output in
#if verify
          Pi.expect (ServerLogBeforeClientCertificateDHE_Auth(si,log));
#endif
          let ps = serverState ci (ClientCertificateDHE(si,dhp,gx,x,log)) in
          (* Compute the next state of the server *)
            correct (
              {state with hs_outgoing = output;
                          pstate = ps},
               si.protocol_version)
        else
          let output = serverHelloB @| certificateB @| serverKEXB @| serverHelloDoneBytes in
          (* Log the output and put it into the output buffer *)
          let log = log @| output in
#if verify
          Pi.expect (ServerLogBeforeClientCertificateDHE_NoAuth(si,log));
#endif
          let ps = serverState ci (ClientKeyExchangeDHE(si,dhp,gx,x,log)) in
            correct (
              {state with hs_outgoing = output;
                          pstate = ps},
               si.protocol_version)

let prepare_server_output_full_DH_anon (ci:ConnectionInfo) (state:hs_state) (si:SessionInfo) (sExtL:list<serverExtension>) (log:log) : Result<(hs_state * ProtocolVersion)> =
#if verify
    failwith "not verifying DH_anon"
#else
    let ext = serverExtensionsBytes sExtL in
    let serverHelloB = serverHelloBytes si si.init_srand ext in

    (* ServerKEyExchange *)

    let default_params_filename = state.poptions.dhDefaultGroupFileName in
    let ops = state.poptions in
    let dhstrength = ops.dhPQMinLength in
    let (dhdb,dhp,y,x) = DH.serverGen default_params_filename state.dhdb dhstrength in
    let state = {state with dhdb = dhdb} in

    let serverKEXB = serverKeyExchangeBytes_DH_anon dhp.dhp dhp.dhg y in

    let output = serverHelloB @|serverKEXB @| serverHelloDoneBytes in
    (* Log the output and put it into the output buffer *)
    let log = log @| output in
    (* Compute the next state of the server *)
    let ps = serverState ci (ClientKeyExchangeDH_anon(si,dhp,y,x,log)) in
    correct ({state with hs_outgoing = output;
                         pstate = ps},
             si.protocol_version)
#endif

let prepare_server_output_full ci state si cv sExtL log =
    if isAnonCipherSuite si.cipher_suite then
        prepare_server_output_full_DH_anon ci state si sExtL log
    elif isDHCipherSuite si.cipher_suite then
        prepare_server_output_full_DH      ci state si sExtL log
    elif isDHECipherSuite si.cipher_suite then
        // Get the client supported SignatureAndHash algorithms. In TLS 1.2, this should be extracted from a client extension
        let calgs = default_sigHashAlg si.protocol_version si.cipher_suite in
        prepare_server_output_full_DHE ci state si calgs sExtL log
    elif isRSACipherSuite si.cipher_suite then
        // Get the client supported SignatureAndHash algorithms. In TLS 1.2, this should be extracted from a client extension
        let calgs = default_sigHashAlg si.protocol_version si.cipher_suite in
        prepare_server_output_full_RSA ci state si cv calgs sExtL log
    else
        unexpected "[prepare_server_output_full] unexpected ciphersuite"

// The server "negotiates" its first proposal included in the client's proposal
let negotiate cList sList =
    List.tryFind (fun s -> List.exists (fun c -> c = s) cList) sList

let prepare_server_output_resumption ci state crand cExtL (sid:sessionID) storedSession cvd svd log =
    let (si,ms) = storedSession in
    let srand = Nonce.mkHelloRandom () in
    let (sExtL,nExtL) = negotiateServerExtensions cExtL state.poptions si.cipher_suite (cvd,svd) true in
    let ext = serverExtensionsBytes sExtL in
    let sHelloB = serverHelloBytes si srand ext in

    let log = log @| sHelloB in
    let next_ci = getNextEpochs ci si crand srand in
    let nki_in = id next_ci.id_in in
    let nki_out = id next_ci.id_out in
    let (reader,writer) = PRF.keyGenServer nki_in nki_out ms in
#if verify
    Pi.expect (ServerLogBeforeServerFinishedResume(crand,srand,si,log));
#endif
    {state with hs_outgoing = sHelloB;
                pstate = PSServer(ServerWritingCCSResume(next_ci.id_out,writer,
                                                         next_ci.id_in,reader,
                                                         ms,log))}

let startServerFull (ci:ConnectionInfo) state (cHello:ProtocolVersion * crand * sessionID * cipherSuites * list<Compression> * bytes) cExtL cvd svd log =
    let (ch_client_version,ch_random,ch_session_id,ch_cipher_suites,ch_compression_methods,ch_extensions) = cHello in
    let cfg = state.poptions in
    // Negotiate the protocol parameters
    let version = minPV ch_client_version cfg.maxVer in
    if (geqPV version cfg.minVer) = false then
        Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation")
    else
        match negotiate ch_cipher_suites cfg.ciphersuites with
        | Some(cs) ->
            (match negotiate ch_compression_methods cfg.compressions with
            | Some(cm) ->
                let sid = Nonce.random 32 in
                let srand = Nonce.mkHelloRandom () in
                let (sExtL, nExtL) = negotiateServerExtensions cExtL cfg cs (cvd, svd) false in
                (* Fill in the session info we're establishing *)
                let si = { clientID         = [];
                           clientSigAlg = (SA_RSA,SHA);
                           client_auth      = cfg.request_client_certificate;
                           serverID         = [];
                           serverSigAlg = (SA_RSA,SHA);
                           sessionID        = sid;
                           protocol_version = version;
                           cipher_suite     = cs;
                           compression      = cm;
                           extensions       = nExtL;
                           init_crand       = ch_random;
                           init_srand       = srand;
                           pmsId            = noPmsId;
                           session_hash     = empty_bytes}
                in
                prepare_server_output_full ci state si ch_client_version sExtL log
            | None -> Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation"))
        | None ->     Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation")

let rec recv_fragment_server (ci:ConnectionInfo) (state:hs_state) (agreedVersion:option<ProtocolVersion>) =
    match parseMessageState ci state with
    | Error(z) -> let (x,y) = z in  InError(x,y,state)
    | Correct(res) ->
      match res with
      | None ->
          (match agreedVersion with
          | None      -> InAck(state)
          | Some (pv) -> InVersionAgreed(state,pv))
      | Some (res) ->
      let (state,hstype,payload,to_log) = res in
      match state.pstate with
      | PSServer(sState) ->
        (match hstype with
        | HT_client_hello ->
            (match sState with
            | ClientHello(cvd,svd) | ServerIdle(cvd,svd) ->
                (match parseClientHello payload with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct (cHello) ->
                let (ch_client_version,ch_random,ch_session_id,ch_cipher_suites,ch_compression_methods,ch_extensions) = cHello in
                (* Log the received message *)
                let log = to_log in
                (* handle extensions *)
                match parseClientExtensions ch_extensions ch_cipher_suites with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct(cExtL) ->
                    if checkClientRenegotiationInfoExtension state.poptions cExtL cvd then
                        if length ch_session_id = 0 then
                            (* Client asked for a full handshake *)
                            match startServerFull ci state cHello cExtL cvd svd log with
                            | Error(z) -> let (x,y) = z in  InError(x,y,state)
                            | Correct(v) ->
                                let (state,pv) = v in
                                let spv = somePV pv in
                                  recv_fragment_server ci state spv
                        else
                            (* Client asked for resumption, let's see if we can satisfy the request *)
                            match SessionDB.select state.sDB ch_session_id Server state.poptions.client_name with
                            | Some sentry ->
                                (let (storedSinfo,_)  = sentry in
                                if geqPV ch_client_version storedSinfo.protocol_version
                                  && List.memr ch_cipher_suites storedSinfo.cipher_suite
                                  && List.memr ch_compression_methods storedSinfo.compression
                                then
                                        (* Proceed with resumption *)
                                        let state = prepare_server_output_resumption ci state ch_random cExtL ch_session_id sentry cvd svd log in
                                        recv_fragment_server ci state (somePV(storedSinfo.protocol_version))
                                else
                                  match startServerFull ci state cHello cExtL cvd svd log with
                                    | Correct(v) -> let (state,pv) = v in recv_fragment_server ci state (somePV (pv))
                                    | Error(z) -> let (x,y) = z in  InError(x,y,state))
                            | None ->
                                  (match startServerFull ci state cHello cExtL cvd svd log with
                                    | Correct(v) -> let (state,pv) = v in recv_fragment_server ci state (somePV (pv))
                                    | Error(z) -> let (x,y) = z in  InError(x,y,state))
                    else
                        (* We don't accept an insecure client *)
                        InError(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Safe renegotiation not supported by the peer", state))
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ClientHello arrived in the wrong state",state))

        | HT_certificate ->
            (match sState with
            | ClientCertificateRSA (si,cv,sk,log) ->
                (match parseClientOrServerCertificate payload with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct([]) ->
                    InError(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Client sent empty certificate",state)
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
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Client sent wrong certificate type",state))
            | ClientCertificateDHE (si,dhp,gx,x,log) ->
                // Duplicated code from above.
                (match parseClientOrServerCertificate payload with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct([]) ->
                    InError(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Client sent empty certificate",state)
                | Correct(certs) ->
                    if Cert.is_chain_for_signing certs then
                        let advice = Cert.validate_cert_chain (default_sigHashAlg si.protocol_version si.cipher_suite) certs in
                        match Cert.get_hint certs with
                            | None ->
                                InQuery(certs,false,{state with pstate = PSServer(ServerCheckingCertificateDHE(si,dhp,gx,x,log,certs,to_log))})
                            | Some(name) when advice && (name = state.poptions.client_name) ->
                                InQuery(certs,true,{state with pstate = PSServer(ServerCheckingCertificateDHE(si,dhp,gx,x,log,certs,to_log))})
                            | Some(name) ->
                                InQuery(certs,false,{state with pstate = PSServer(ServerCheckingCertificateDHE(si,dhp,gx,x,log,certs,to_log))})
                    else
                        InError(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Client sent wrong certificate type",state))
            | ClientCertificateDH  (si,log) ->  InError(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Certificate arrived in the wrong state",state))

        | HT_client_key_exchange ->
            (match sState with
            | ClientKeyExchangeRSA(si,cv,sk,log) ->
                (match parseClientKEX_RSA si sk cv state.poptions payload with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct(x) ->
                    let (pk,rsapms) = x in

                    let pms = PMS.RSAPMS(pk,cv,rsapms) in
                    let pmsid = pmsId pms in
                    let si = {si with pmsId = pmsid} in
                    let log = log @| to_log in
                    let (si,ms) = extract si pms log in

                    (* move to new state *)
                    if si.client_auth then (
#if verify
                        Pi.expect(ServerLogBeforeClientCertificateVerifyRSA(si,log));
#endif
                        recv_fragment_server ci
                          {state with pstate = PSServer(CertificateVerify(si,ms,log))}
                          agreedVersion)
                    else (
#if verify
                        Pi.expect(ServerLogBeforeClientCertificateVerifyRSA(si,log));
                        Pi.expect(ServerLogBeforeClientFinished_NoAuth(si,log));
#endif
                        recv_fragment_server ci
                          {state with pstate = PSServer(ClientCCS(si,ms,log))}
                          agreedVersion))
            | ClientKeyExchangeDHE(si,dhp,gx,x,log) ->
                (match parseClientKEXExplicit_DH dhp payload with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct(y) ->
                    let log = log @| to_log in
                    (* from the local state, we know: PP(dhp) /\ ?gx. DHE.Exp(dhp,x,gx) ; tweak the ?gx for genPMS. *)

                    (* these 3 lines implement  ms-KEM(DH).dec where:
                       (pv,h,l) are included in si, sk is ((dhp,gx),x), c is y *)

                    (* these 2 lines implement pms-KEM(DH).dec(pv?, sk, c) *)

                    let dhpms = DH.serverExp dhp gx y x in

                    let pms = PMS.DHPMS(dhp.dhp,dhp.dhg,gx,y,dhpms) in
                    let si_old = si in
                    let si = {si_old with pmsId = pmsId(pms)} in
#if verify
                    Pi.expect(UpdatesPmsID(si_old,si));

#endif
                    (* StrongHS(si) /\ DHE.Exp(dhp,?cx,y) -> DHE.Secret(pms) *)
                    let (si,ms) = extract si pms log in
                    (* StrongHS(si) /\ DHE.Exp(dhp,?cx,y) -> PRFs.Secret(ms) *)

                    (* we rely on scopes & type safety to get forward secrecy*)
                    (* move to new state *)
                    if si.client_auth then (
#if verify
                        Pi.expect(Authorize(Server,si));
                        Pi.expect(UpdatesPmsID(si_old,si));
                        Pi.expect(ServerLogBeforeClientCertificateVerifyDHE(si,log));
                        Pi.expect(ServerLogBeforeClientCertificateVerify(si,log));
#endif
                        recv_fragment_server ci
                          {state with pstate = PSServer(CertificateVerify(si,ms,log))}
                          agreedVersion)
                    else (
#if verify
                        Pi.expect(ServerLogBeforeClientCertificateVerifyDHE(si,log));
                        Pi.expect(ServerLogBeforeClientFinished_NoAuth(si,log));
#endif
                        recv_fragment_server ci
                          {state with pstate = PSServer(ClientCCS(si,ms,log))}
                          agreedVersion))
#if verify
#else
            | ClientKeyExchangeDH_anon(si,dhp,gx,x,log) ->
                (match parseClientKEXExplicit_DH dhp payload with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct(y) ->
                    let log = log @| to_log in

                    let dhpms = DH.serverExp dhp gx y x in

                    let pms = PMS.DHPMS(dhp.dhp,dhp.dhg,gx,y,dhpms) in
                    let (si,ms) = extract si pms log in

                    (* move to new state *)
                    recv_fragment_server ci
                      {state with pstate = PSServer(ClientCCS(si,ms,log))}
                      agreedVersion)
#endif
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ClientKeyExchange arrived in the wrong state",state))

        | HT_certificate_verify ->
            (match sState with
            | CertificateVerify(si,ms,log) ->
                let allowedAlgs = default_sigHashAlg si.protocol_version si.cipher_suite in // In TLS 1.2, these are the same as we sent in CertificateRequest
                let (verifyOK,a,_) = certificateVerifyCheck si ms allowedAlgs log payload in
                if verifyOK then// payload then
                    let si' = {si with clientSigAlg = a} in
                    let log = log @| to_log in
#if verify
                        Pi.expect(Authorize(Server,si'));
                        Pi.expect(ServerLogBeforeClientFinished_Auth(si',log));
                        Pi.expect(UpdatesClientSigAlg(si,si'));
#endif
                    recv_fragment_server ci
                      {state with pstate = PSServer(ClientCCS(si',ms,log))}
                      agreedVersion
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Certificate verify check failed",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CertificateVerify arrived in the wrong state",state))

        | HT_finished ->
            (match sState with
            | ClientFinished(si,ms,e,w,log) ->
                if PRF.checkVerifyData si ms Client log payload then
                    let log = log @| to_log in
#if verify
                    Pi.expect(ServerLogBeforeServerFinished(si,log));
#endif
                    InFinished({state with pstate = PSServer(ServerWritingCCS(si,ms,e,w,payload,log))})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | ClientFinishedResume(si,ms,e,svd,log) ->
                if PRF.checkVerifyData si ms Client log payload then
                    (
#if verify
                    Pi.expect (Complete(ci));
#endif
                    check_negotiation Server si state.poptions;
                    InComplete({state with pstate = PSServer(ServerIdle(payload,svd))}))
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Finished arrived in the wrong state",state))

        | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Unknown message received",state))
      (* Should never happen *)
      | PSClient(_) -> unexpected "[recv_fragment_server] should only be invoked when in server role."

let enqueue_fragment (ci:ConnectionInfo) state fragment =
    let new_inc = state.hs_incoming @| fragment in
    {state with hs_incoming = new_inc}

let recv_fragment ci (state:hs_state) (r:range) (fragment:HSFragment.fragment) =

    let ki_in = id ci.id_in in
    let b = HSFragment.fragmentRepr ki_in r fragment in
    if length b = 0 then
        // Empty HS fragment are not allowed
        InError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Empty handshake fragment received",state)
    else
        let state = enqueue_fragment ci state b in
        match state.pstate with
        | PSClient (_) -> recv_fragment_client ci state None
        | PSServer (_) -> recv_fragment_server ci state None

let recv_ccs (ci:ConnectionInfo) (state: hs_state) (r:range) (fragment:HSFragment.fragment): incomingCCS =

    let ki_in = id ci.id_in in
    let b = HSFragment.fragmentRepr ki_in r fragment in
    if equalBytes b CCSBytes then
        match state.pstate with
        | PSServer (sState) ->
            (match sState with
            | ClientCCS(si,ms,log) ->
                let next_ci = getNextEpochs ci si si.init_crand si.init_srand in
                let nki_in = id next_ci.id_in in
                let nki_out = id next_ci.id_out in
                let (reader,writer) = PRF.keyGenServer nki_in nki_out ms in
                let ci = {ci with id_in = next_ci.id_in} in
                InCCSAck(ci,reader,{state with pstate = PSServer(ClientFinished(si,ms,next_ci.id_out,writer,log))})
            | ClientCCSResume(e,r,svd,ms,log) ->
                let ci = {ci with id_in = e} in
                let si = epochSI e in
                InCCSAck(ci,r,{state with pstate = PSServer(ClientFinishedResume(si,ms,e,svd,log))})
            | _ -> InCCSError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CCS arrived in the wrong state",state))
        | PSClient (cstate) -> // Check that we are in the right state (CCCS)
            (match cstate with
            | ServerCCS(si,ms,e,r,cvd,log) ->
                let ci = {ci with id_in = e} in
                InCCSAck(ci,r,{state with pstate = PSClient(ServerFinished(si,ms,e,cvd,log))})
            | ServerCCSResume(ew,w,er,r,ms,log) ->
                let ci = {ci with id_in = er} in
                InCCSAck(ci,r,{state with pstate = PSClient(ServerFinishedResume(ew,w,ms,log))})
            | _ -> InCCSError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "CCS arrived in the wrong state",state))
    else           InCCSError(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "",state)

let getMinVersion (ci:ConnectionInfo) state =
  let pop = state.poptions in
  pop.minVer

let authorize (ci:ConnectionInfo) (state:hs_state) (q:Cert.chain) =
    let pstate = state.pstate in
    match pstate with
    | PSClient(cstate) ->
        (match cstate with
        | ClientCheckingCertificateRSA(si,log,certs,agreedVersion,to_log) when certs = q ->

            if certs = q then
              let log = log @| to_log in
              let si' = {si with serverID = certs} in
              Pi.assume (Authorize(Client,si')); // ``The user authorizes q as peer serverID''
#if verify
              Pi.expect (UpdatesServerID(si,si'));
#endif
              recv_fragment_client ci
                {state with pstate = PSClient(CertificateRequestRSA(si',log))}
                agreedVersion
            else unexpected "[authorize] invoked with different cert"
        | ClientCheckingCertificateDHE(si,log,certs,agreedVersion,to_log) when certs = q ->
            let log = log @| to_log in
            let si = {si with serverID = certs} in
            Pi.assume (Authorize(Client,si)); // ``The user authorizes q as peer serverID''
            recv_fragment_client ci
              {state with pstate = PSClient(ServerKeyExchangeDHE(si,log))}
              agreedVersion
        // | ClientCheckingCertificateDH -> TODO
        | _ -> unexpected "[authorize] invoked on the wrong state")
    | PSServer(sstate) ->
        (match sstate with
        | ServerCheckingCertificateRSA(si,cv,sk,log,c,to_log) when c = q ->
            let log = log @| to_log in
            let si' = {si with clientID = q} in
            Pi.assume (Authorize(Server,si')); // ``The user authorizes q as peer clientID''
#if verify
            Pi.expect (UpdatesClientID(si,si'));
            Pi.expect (ServerLogBeforeClientKeyExchangeRSA_Auth(si',cv,log));
#endif
            recv_fragment_server ci
              {state with pstate = PSServer(ClientKeyExchangeRSA(si',cv,sk,log))}
              None

        | ServerCheckingCertificateDHE(si,dhp,gx,x,log,c,to_log) when c = q ->
            let log = log @| to_log in
            let si' = {si with clientID = q} in
            Pi.assume (Authorize(Server,si')); // ``The user authorizes q as peer clientID''
#if verify
            Pi.expect (UpdatesClientID(si,si'));
            Pi.expect (ServerLogBeforeClientKeyExchangeDHE_Auth(si',log));
#endif
            recv_fragment_server ci
              {state with pstate = PSServer(ClientKeyExchangeDHE(si',dhp,gx,x,log))}
              None
        // | ServerCheckingCertificateDH -> TODO
        | _ -> unexpected "[authorize] invoked on the wrong state")

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
