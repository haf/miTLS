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

module Handshake
// State machine begins
open Bytes
open Error
open TLSError
open TLSConstants
open TLSExtensions
open TLSInfo
open Range
open HandshakeMessages

type events =
    Authorize of Role * SessionInfo
  | Configure of Role * epoch * config
  | EvSentFinishedFirst of ConnectionInfo * bool
  | Negotiated of Role * SessionInfo * config * config

(* verify data authenticated by the Finished messages *)
type log = bytes         (* message payloads so far, to be eventually authenticated *)

// The constructor indicates either what we are doing locally or which peer message we are expecting,

type serverState =  (* note that the CertRequest bits are determined by the config *)
                    (* we may omit some ProtocolVersion, mostly a ghost variable *)
   | ClientHello                  of cVerifyData * sVerifyData

   | ClientCertificateRSA         of SessionInfo * ProtocolVersion * RSAKey.sk * log
   | ServerCheckingCertificateRSA of SessionInfo * ProtocolVersion * RSAKey.sk * log * Cert.chain * bytes
   | ClientKeyExchangeRSA         of SessionInfo * ProtocolVersion * RSAKey.sk * log

   | ClientCertificateDH         of SessionInfo * log
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
   | ServerHello                  of crand * sessionID * clientExtension list * cVerifyData * sVerifyData * log

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
  sDB: SessionDB.t;
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
        Pi.assume (Configure(Client,ci.id_in,poptions));
        let extL = prepareClientExtensions poptions ci empty_bytes None in
        let ext = clientExtensionsBytes extL in
        let cHelloBytes = clientHelloBytes poptions rand sid ext in
        let sdb = SessionDB.create poptions in
        (ci,{hs_outgoing = cHelloBytes;
                     hs_incoming = empty_bytes;
                     poptions = poptions;
                     sDB = sdb;
                     pstate = PSClient (ServerHello (rand, sid, extL, empty_bytes, empty_bytes, cHelloBytes))
            })
    | Server ->
        let ci = initConnection role rand in
        Pi.assume (Configure(Client,ci.id_in,poptions));
        let sdb = SessionDB.create poptions in
        (ci,{hs_outgoing = empty_bytes
             hs_incoming = empty_bytes
             poptions = poptions
             sDB = sdb
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
    let rand = Nonce.mkHelloRandom () in
    let ci = initConnection Client rand in
    Pi.assume (Configure(Server,ci.id_in,poptions));
    let extL = prepareClientExtensions poptions ci empty_bytes None
    let ext = clientExtensionsBytes extL
    let cHelloBytes = clientHelloBytes poptions rand sid ext in
    let sdb = SessionDB.create poptions
    (ci,{hs_outgoing = cHelloBytes
         hs_incoming = empty_bytes
         poptions = poptions
         sDB = sdb
         pstate = PSClient (ServerHello (rand, sid, extL, empty_bytes, empty_bytes, cHelloBytes))
        })

let rehandshake (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    (* Start a non-resuming handshake, over an existing epoch.
       Only client side, since a server can only issue a HelloRequest *)
    match state.pstate with
    | PSClient (cstate) ->
        match cstate with
        | ClientIdle(cvd,svd) ->
            let rand = Nonce.mkHelloRandom () in
            let sid = empty_bytes in
            let extL = prepareClientExtensions ops ci cvd None in
            let ext = clientExtensionsBytes extL in
            let cHelloBytes = clientHelloBytes ops rand sid ext in
            Pi.assume (Configure(Client,ci.id_in,ops));
            let sdb = SessionDB.create ops
            (true,{hs_outgoing = cHelloBytes
                   hs_incoming = empty_bytes
                   poptions = ops
                   sDB = sdb
                   pstate = PSClient (ServerHello (rand, sid, extL, cvd,svd, cHelloBytes))
                   })
        | _ -> (* handshake already happening, ignore this request *)
            (false,state)
    | PSServer (_) -> unexpected "[rehandshake] should only be invoked on client side connections."

let rekey (ci:ConnectionInfo) (state:hs_state) (ops:config) =
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
        match SessionDB.select sDB sid Client ops.server_name with
        | None -> (* Maybe session expired, or was never stored. Let's not resume *)
            rehandshake ci state ops
        | Some s ->
            let (retrievedSinfo,retrievedMS) = s
            match state.pstate with
            | PSClient (cstate) ->
                match cstate with
                | ClientIdle(cvd,svd) ->
                    let rand = Nonce.mkHelloRandom () in
                    let extL = prepareClientExtensions ops ci cvd None
                    let ext = clientExtensionsBytes extL in
                    Pi.assume (Configure(Client,ci.id_in,ops));
                    let cHelloBytes = clientHelloBytes ops rand sid ext in
                    (true,{hs_outgoing = cHelloBytes
                           hs_incoming = empty_bytes
                           poptions = ops
                           sDB = sDB
                           pstate = PSClient (ServerHello (rand, sid, extL, cvd, svd, cHelloBytes))
                           })
                | _ -> (* Handshake already ongoing, ignore this request *)
                    (false,state)
            | PSServer (_) -> unexpected "[rekey] should only be invoked on client side connections."

let request (ci:ConnectionInfo) (state:hs_state) (ops:config) =
    match state.pstate with
    | PSClient _ -> unexpected "[request] should only be invoked on server side connections."
    | PSServer (sstate) ->
        match sstate with
        | ServerIdle(cvd,svd) ->
            let sdb = SessionDB.create ops
            (* Put HelloRequest in outgoing buffer (and do not log it), and move to the ClientHello state (so that we don't send HelloRequest again) *)
            (true, { hs_outgoing = helloRequestBytes
                     hs_incoming = empty_bytes
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
  let i = isInitEpoch(ci.id_in) in
    if i = true then
        state
    else
        let si = epochSI(ci.id_in)
        match si.sessionID with
        | xx when length xx = 0 -> state
        | sid ->
            let hint = getPrincipal ci state
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
        match state.pstate with
        | PSClient(cstate) ->
            match cstate with
            | ClientWritingCCS (si,ms,log) ->
                let next_ci = getNextEpochs ci si si.init_crand si.init_srand in
                let nki_in = id next_ci.id_in in
                let nki_out = id next_ci.id_out in
                let (reader,writer) = PRF.keyGenClient nki_in nki_out ms in
                Pi.assume (SentCCS(Client,next_ci.id_out));

                let cvd = PRF.makeVerifyData si ms Client log in
                let cFinished = messageBytes HT_finished cvd in
                let log = log @| cFinished in
                let ki_out = ci.id_out in
                let (rg,f,_) = makeFragment ki_out CCSBytes in
                let ci = {ci with id_out = next_ci.id_out} in

                OutCCS(rg,f,ci,writer,
                       {state with hs_outgoing = cFinished
                                   pstate = PSClient(ServerCCS(si,ms,next_ci.id_in,reader,cvd,log))})

            | ClientWritingCCSResume(e,w,ms,svd,log) ->
                Pi.assume (SentCCS(Client,e));
                let cvd = PRF.makeVerifyData (epochSI e) ms Client log in
                let cFinished = messageBytes HT_finished cvd in
                let ki_out = ci.id_out in
                let (rg,f,_) = makeFragment ki_out CCSBytes in
                let ci = {ci with id_out = e} in

                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = cFinished
                                   pstate = PSClient(ClientWritingFinishedResume(cvd,svd))})

            | _ -> OutIdle(state)
        | PSServer(sstate) ->
            match sstate with
            | ServerWritingCCS (si,ms,e,w,cvd,log) ->
                Pi.assume (SentCCS(Server,e));
                let svd = PRF.makeVerifyData si ms Server log in
                let sFinished = messageBytes HT_finished svd in
                let ki_out = ci.id_out in
                let (rg,f,_) = makeFragment ki_out CCSBytes in
                let ci = {ci with id_out = e} in

                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = sFinished
                                   pstate = PSServer(ServerWritingFinished(si,ms,e,cvd,svd))})

            | ServerWritingCCSResume(we,w,re,r,ms,log) ->
                Pi.assume (SentCCS(Server,we));
                let svd = PRF.makeVerifyData (epochSI we) ms Server log in
                let sFinished = messageBytes HT_finished svd in
                let log = log @| sFinished in
                let ki_out = ci.id_out in
                let (rg,f,_) = makeFragment ki_out CCSBytes in
                let ci = {ci with id_out = we} in

                OutCCS(rg,f,ci,w,
                       {state with hs_outgoing = sFinished
                                   pstate = PSServer(ClientCCSResume(re,r,svd,ms,log))})

            | _ -> OutIdle(state)
    | outBuf ->
        let ki_out = ci.id_out in
        let (rg,f,remBuf) = makeFragment ki_out outBuf in
        match remBuf with
        | xx when length xx = 0 ->
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
                    if length si.sessionID = 0 then
                      check_negotiation Server si state.poptions;
                      OutComplete(rg,f,
                                  {state with hs_outgoing = remBuf
                                              pstate = PSServer(ServerIdle(cvd,svd))})

                    else
                      let sdb = SessionDB.insert state.sDB si.sessionID Server state.poptions.client_name (si,ms)
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
    | _ when si.client_auth = false -> empty_bytes,[]

let getCertificateVerifyBytes (si:SessionInfo) (ms:PRF.masterSecret) (cert_req:(Cert.chain * Sig.alg * Sig.skey) option) (l:log) =
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

let prepare_client_output_full_RSA (ci:ConnectionInfo) (state:hs_state) (si:SessionInfo) (cert_req:Cert.sign_cert) (log:log) : (hs_state * SessionInfo * PRF.masterSecret * log) Result =
    let clientCertBytes,certList = getCertificateBytes si cert_req in
    let si = {si with clientID = certList}
    let log = log @| clientCertBytes in

    match clientKEXBytes_RSA si state.poptions with
    | Error(z) -> Error(z)
    | Correct(v) ->
    let (clientKEXBytes,pmsdata,rsapms)  = v in

    let pk =
        match Cert.get_chain_public_encryption_key si.serverID with
        | Correct(pk) -> pk
        | _           -> unexpected "server must have an ID"
    let spop = state.poptions in
    let cv = spop.maxVer in
    let pms = PMS.RSAPMS(pk,cv,rsapms)
    let pmsid = pmsId pms
    let si = {si with pmsId = pmsid; pmsData = pmsdata} in
    let log = log @| clientKEXBytes in
    let ms = CRE.extract si pms in

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
  else (si,empty_bytes)

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

let prepare_client_output_full_DHE (ci:ConnectionInfo) (state:hs_state) (si:SessionInfo) (cert_req:Cert.sign_cert) (p:DHGroup.p) (g:DHGroup.g) (sy:DHGroup.elt) (log:log) : (hs_state * SessionInfo * PRF.masterSecret * log) Result =

    (* pre: Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> DHE.PP((p,g)) /\ ServerDHE((p,g),sy,si.init_crand @| si.init_srand) *)
    (* moreover, by definition ServerDHE((p,g),sy,si.init_crand @| si.init_srand) implies ?sx.DHE.Exp((p,g),sx,sy) *)

    let (si,clientCertBytes) = sessionInfoCertBytesAuth si cert_req in

    let log = log @| clientCertBytes

    let (cy,x) = DH.genKey p g in
    (* post: DHE.Exp((p,g),x,cy) *)

    let dhpms = DH.exp p g cy sy x in
    let pms = PMS.DHPMS(p,g,cy,sy,dhpms) in
    let si = {si with pmsData = DHPMS(p,g,cy,sy);
                      pmsId = pmsId pms} in
    (* si is now constant *)

    let clientKEXBytes = clientKEXExplicitBytes_DH cy in
    let log = log @| clientKEXBytes in

    (* the post of this call is !sx,cy. PP((p,g) /\ DHE.Exp((p,g),x,cy)) /\ DHE.Exp((p,g),sx,sy) -> DHE.Secret((p,g),cy,sy) *)
    (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> DHE.Secret((p,g),cy,sy) *)
    let ms = CRE.extract si pms in
    (* the post of this call is !p,g,gx,gy. StrongHS(si) /\ DHE.Secret((p,g),gx,gy) -> PRFs.Secret(ms) *)
    (* thus we have Honest(verifyKey(si.server_id)) /\ StrongHS(si) -> PRFs.Secret(ms) *)

    let certificateVerifyBytes = certificateVerifyBytesAuth si ms cert_req log in

    let log = log @| certificateVerifyBytes in

    let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
    let new_outgoing = state.hs_outgoing @| to_send in
    correct ({state with hs_outgoing = new_outgoing},si,ms,log)
(* #endif *)

let on_serverHello_full (ci:ConnectionInfo) crand log to_log (shello:ProtocolVersion * srand * sessionID * cipherSuite * Compression * bytes) extL =
    let log = log @| to_log in
    let (sh_server_version,sh_random,sh_session_id,sh_cipher_suite,sh_compression_method,sh_neg_extensions) = shello
    let si = { clientID = []
               client_auth = false
               serverID = []
               sessionID = sh_session_id
               protocol_version = sh_server_version
               cipher_suite = sh_cipher_suite
               compression = sh_compression_method
               extensions = extL
               init_crand = crand
               init_srand = sh_random
               pmsId = noPmsId
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

let rec recv_fragment_client (ci:ConnectionInfo) (state:hs_state) (agreedVersion:ProtocolVersion option) =
    match parseMessageState ci state with
    | Error z -> let (x,y) = z in InError(x,y,state)
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
            | ServerHello (crand,sid,cExtL,cvd,svd,log) ->
                match parseServerHello payload with
                | Error z -> let (x,y) = z in InError(x,y,state)
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
                  match parseServerExtensions sh_neg_extensions with
                  | Error z ->
                      let (x,y) = z in

                      InError(x,y,state)

                  | Correct(sExtL) ->
                  // Handling of safe renegotiation //#begin-safe_renego
                  if checkServerRenegotiationInfoExtension state.poptions sExtL cvd svd then
                    //#end-safe_renego
                    // Log the received message.
                    (* Check whether we asked for resumption *)
                    if (length sid = 0) || (not (equalBytes sid sh_session_id)) then
                        (* we did not request resumption, or the server didn't accept it: do a full handshake *)
                        (* define the sinfo we're going to establish *)
                        match negotiateClientExtensions cExtL sExtL false (* Not resuming *) with
                        | Error(x,y) -> InError(x,y,state)
                        | Correct(nExtL) ->
                            let next_pstate = on_serverHello_full ci crand log to_log shello nExtL in

                            recv_fragment_client ci {state with pstate = next_pstate}  (Some sh_server_version)

                    else
                        (* use resumption *)
                        (* Search for the session in our DB *)
                        match SessionDB.select state.sDB sid Client state.poptions.server_name with
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
                                    let nki_in = id next_ci.id_in in
                                    let nki_out = id next_ci.id_out in
                                    let (reader,writer) = PRF.keyGenClient nki_in nki_out ms in
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

                  else
                    InError (AD_handshake_failure,perror __SOURCE_FILE__ __LINE__ "Wrong renegotiation information provided",state)

            | _ ->

                InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerHello arrived in the wrong state",state)

        | HT_certificate ->
            match cState with
            // Most of the code in the branches is duplicated, but it helps for verification
            | ServerCertificateRSA (si,log) ->
                match parseClientOrServerCertificate payload with
                | Error z ->
                    let (x,y) = z in

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
                | Error z ->
                    let (x,y) = z in

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
                | Error z ->
                    let (x,y) = z in

                    InError(x,y,state)

                | Correct(v) ->
                    let (p,g,y,alg,signature) = v in
                    match Cert.get_chain_public_signing_key si.serverID alg with
                    | Error z ->
                        let (x,y) = z in

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
                | Error z -> let (x,y) = z in InError(x,y,state)
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
                | Error z -> let (x,y) = z in  InError(x,y,state)
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
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
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
                if length payload = 0 then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_RSA ci state si None log with
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
            | CertificateRequestDHE(si,p,g,y,log) | ServerHelloDoneDH_anon(si,p,g,y,log) ->
                if length payload = 0 then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_DHE ci state si None p g y log with
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
            | ServerHelloDoneDHE(si,skey,p,g,y,log) ->
                if length  payload = 0 then
                    (* Log the received packet *)
                    let log = log @| to_log in

                    match prepare_client_output_full_DHE ci state si skey p g y log with
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
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ServerHelloDone arrived in the wrong state",state)

        | HT_finished ->
            match cState with
            | ServerFinished(si,ms,e,cvd,log) ->
                if PRF.checkVerifyData si ms Server log payload then
                    let sDB =
                        if length  si.sessionID = 0 then state.sDB
                        else SessionDB.insert state.sDB si.sessionID Client state.poptions.server_name (si,ms)
                    check_negotiation Client si state.poptions;
                    InComplete({state with pstate = PSClient(ClientIdle(cvd,payload)); sDB = sDB})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | ServerFinishedResume(e,w,ms,log) ->
                if PRF.checkVerifyData (epochSI ci.id_in) ms Server log payload then
                    let log = log @| to_log in
                    InFinished({state with pstate = PSClient(ClientWritingCCSResume(e,w,ms,payload,log))})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Finished arrived in the wrong state",state)
        | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Unrecognized message",state)

      (* Should never happen *)
      | PSServer(_) -> unexpected "[recv_fragment_client] should only be invoked when in client role."

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

let prepare_server_output_full_DH ci state si sExtL log =
  Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "Unimplemented")

let prepare_server_output_full_DHE (ci:ConnectionInfo) state si certAlgs sExtL log =
    let ext = serverExtensionsBytes sExtL in
    let serverHelloB = serverHelloBytes si si.init_srand ext in
    let keyAlgs = sigHashAlg_bySigList certAlgs [sigAlg_of_ciphersuite si.cipher_suite] in
    if List.listLength keyAlgs = 0 then
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

let prepare_server_output_full_DH_anon (ci:ConnectionInfo) state si sExtL log : (hs_state * ProtocolVersion) Result =
    let ext = serverExtensionsBytes sExtL in
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

let prepare_server_output_full ci state si cv sExtL log =
    if isAnonCipherSuite si.cipher_suite then
        prepare_server_output_full_DH_anon ci state si sExtL log
    elif isDHCipherSuite si.cipher_suite then
        prepare_server_output_full_DH ci state si sExtL log
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

let prepare_server_output_resumption ci state crand cExtL si ms cvd svd log =
    let srand = Nonce.mkHelloRandom () in
    let (sExtL,nExtL) = negotiateServerExtensions cExtL state.poptions ci (cvd,svd) None
    let ext = serverExtensionsBytes sExtL in
    let sHelloB = serverHelloBytes si srand ext in

    let log = log @| sHelloB
    let next_ci = getNextEpochs ci si crand srand in
    let nki_in = id next_ci.id_in in
    let nki_out = id next_ci.id_out in
    let (reader,writer) = PRF.keyGenServer nki_in nki_out ms in
    {state with hs_outgoing = sHelloB
                pstate = PSServer(ServerWritingCCSResume(next_ci.id_out,writer,
                                                         next_ci.id_in,reader,
                                                         ms,log))}

let startServerFull (ci:ConnectionInfo) state (cHello:ProtocolVersion * crand * sessionID * cipherSuites * Compression list * bytes) cExtL cvd svd log =
    let (ch_client_version,ch_random,ch_session_id,ch_cipher_suites,ch_compression_methods,ch_extensions) = cHello in
    let cfg = state.poptions in
    let (sExtL, nExtL) = negotiateServerExtensions cExtL cfg ci (cvd, svd) None
    // Negotiate the protocol parameters
    let version = minPV ch_client_version cfg.maxVer in
    if (geqPV version cfg.minVer) = false then
        Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation")
    else
        match negotiate ch_cipher_suites cfg.ciphersuites with
        | Some(cs) ->
            match negotiate ch_compression_methods cfg.compressions with
            | Some(cm) ->
                let sid = Nonce.random 32 in
                let srand = Nonce.mkHelloRandom () in
                (* Fill in the session info we're establishing *)
                let si = { clientID         = []
                           client_auth      = cfg.request_client_certificate
                           serverID         = []
                           sessionID        = sid
                           protocol_version = version
                           cipher_suite     = cs
                           compression      = cm
                           extensions       = nExtL
                           init_crand       = ch_random
                           init_srand       = srand
                           pmsId            = noPmsId
                           pmsData          = PMSUnset
                           extended_record_padding = false }
                prepare_server_output_full ci state si ch_client_version sExtL log
            | None -> Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Compression method negotiation")
        | None ->     Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation")

let rec recv_fragment_server (ci:ConnectionInfo) (state:hs_state) (agreedVersion:ProtocolVersion option) =
    match parseMessageState ci state with
    | Error(z) -> let (x,y) = z in  InError(x,y,state)
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
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct (cHello) ->
                let (ch_client_version,ch_random,ch_session_id,ch_cipher_suites,ch_compression_methods,ch_extensions) = cHello
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
                                let (storedSinfo,storedMS)  = sentry in
                                if geqPV ch_client_version storedSinfo.protocol_version
                                  && List.memr ch_cipher_suites storedSinfo.cipher_suite
                                  && List.memr ch_compression_methods storedSinfo.compression
                                then
                                  (* Proceed with resumption *)
                                  let state = prepare_server_output_resumption ci state ch_random cExtL storedSinfo storedMS cvd svd log in
                                  recv_fragment_server ci state (somePV(storedSinfo.protocol_version))
                                else
                                  match startServerFull ci state cHello cExtL cvd svd log with
                                    | Correct(v) -> let (state,pv) = v in recv_fragment_server ci state (somePV (pv))
                                    | Error(z) -> let (x,y) = z in  InError(x,y,state)
                            | None ->
                                  match startServerFull ci state cHello cExtL cvd svd log with
                                    | Correct(v) -> let (state,pv) = v in recv_fragment_server ci state (somePV (pv))
                                    | Error(z) -> let (x,y) = z in  InError(x,y,state)
                    else
                        (* We don't accept an insecure client *)
                        InError(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Safe renegotiation not supported by the peer", state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "ClientHello arrived in the wrong state",state)

        | HT_certificate ->
            match sState with
            | ClientCertificateRSA (si,cv,sk,log) ->
                match parseClientOrServerCertificate payload with
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
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
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
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
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct(res) ->
                    let (pmsdata,rsapms) = res in

                    let pk =
                        match Cert.get_chain_public_encryption_key si.serverID with
                        | Correct(pk) -> pk
                        | _           -> unexpected "server must have an ID"
                    let pms = PMS.RSAPMS(pk,cv,rsapms)
                    let pmsid = pmsId pms
                    let si = {si with pmsId = pmsid; pmsData = pmsdata} in
                    let log = log @| to_log in
                    let ms = CRE.extract si pms in

                    (* move to new state *)
                    if si.client_auth then
#if verify
                        Pi.expect(ServerLogBeforeClientCertificateVerifyRSA(si,log));
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
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct(y) ->
                    let log = log @| to_log in
                    let si = {si with pmsData = DHPMS(p,g,y,gx)} in
                    (* from the local state, we know: PP((p,g)) /\ ?gx. DHE.Exp((p,g),x,gx) ; tweak the ?gx for genPMS. *)
                    let dhpms = DH.exp p g gx y x in

                    let pms = PMS.DHPMS(p,g,y,gx,dhpms) in
                    (* StrongHS(si) /\ DHE.Exp((p,g),?cx,y) -> DHE.Secret(pms) *)
                    let ms = CRE.extract si pms in
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
                | Error(z) -> let (x,y) = z in  InError(x,y,state)
                | Correct(y) ->
                    let log = log @| to_log in

                    let dhpms = DH.exp p g gx y x in
                    let pms = PMS.DHPMS(p,g,y,gx,dhpms) in
                    let ms = CRE.extract si pms in

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
                if PRF.checkVerifyData si ms Client log payload then
                    let log = log @| to_log in
                    InFinished({state with pstate = PSServer(ServerWritingCCS(si,ms,e,w,payload,log))})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | ClientFinishedResume(si,ms,e,svd,log) ->
                if PRF.checkVerifyData si ms Client log payload then
                    check_negotiation Server si state.poptions;
                    InComplete({state with pstate = PSServer(ServerIdle(payload,svd))})
                else
                    InError(AD_decrypt_error, perror __SOURCE_FILE__ __LINE__ "Verify data did not match",state)
            | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Finished arrived in the wrong state",state)

        | _ -> InError(AD_unexpected_message, perror __SOURCE_FILE__ __LINE__ "Unknown message received",state)
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
                let nki_in = id next_ci.id_in in
                let nki_out = id next_ci.id_out in
                let (reader,writer) = PRF.keyGenServer nki_in nki_out ms in
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
            else unexpected "[authorize] invoked with different cert"
        | ClientCheckingCertificateDHE(si,log,agreedVersion,to_log) ->
            let log = log @| to_log in
            let si = {si with serverID = q} in
            Pi.assume (Authorize(Client,si));
            recv_fragment_client ci
              {state with pstate = PSClient(ServerKeyExchangeDHE(si,log))}
              agreedVersion
        // | ClientCheckingCertificateDH -> TODO
        | _ -> unexpected "[authorize] invoked on the wrong state"
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
        | _ -> unexpected "[authorize] invoked on the wrong state"

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
