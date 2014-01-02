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

module PRF

open Error
open Bytes
open TLSConstants
open TLSPRF
open TLSInfo

type repr = bytes
type masterSecret = { bytes: repr }

#if ideal
let log = ref []
let finish_log = ref []
let corrupted = ref []

let strong si = true
let corrupt si = memr !corrupted si
let honest si = if corrupt si then false else true

let sample (si:SessionInfo) = {bytes = Nonce.mkRandom 48}

// we normalize the pair to use as a shared index;
// this function could also leave in TLSInfo
let epochs (ci:ConnectionInfo) =
  if ci.role = Client
  then (ci.id_in, ci.id_out)
  else (ci.id_out, ci.id_in)
#endif

let keyGen ci (ms:masterSecret) =
    let si = epochSI(ci.id_in) in
    let pv = si.protocol_version in
    let cs = si.cipher_suite in
    let srand = epochSRand ci.id_in in
    let crand = epochCRand ci.id_in in
    let data = srand @| crand in
    let len = getKeyExtensionLength pv cs in
    let b = prf pv cs ms.bytes tls_key_expansion data len in
    //#begin-ideal1
    #if ideal

    if honest (epochSI(ci.id_in))
    then
        match tryFind (fun el-> fst el = (epochs ci,ms)) !log with
        | Some(_,(cWrite,cRead)) -> (cWrite,cRead)
        | None                    ->
            let (myWrite,peerRead) = StatefulLHAE.GEN ci.id_out
            let (peerWrite,myRead) = StatefulLHAE.GEN ci.id_in
            log := ((epochs ci,ms),(peerWrite,peerRead))::!log;
            (myWrite,myRead)
    else
    //#end-ideal1
    #endif
        let authEnc = authencAlg_of_ciphersuite cs pv in
        match authEnc with
        | MACOnly macAlg ->
            let macKeySize = macKeySize macAlg in
            let ck,sk = split b macKeySize
            match ci.role with
            | Client ->
                (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState ck,
                 StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState sk)
            | Server ->
                (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState sk,
                 StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState ck)
        | MtE(encAlg,macAlg) ->
            let macKeySize = macKeySize macAlg in
            let encKeySize = encKeySize encAlg in
            match encAlg with
            | Stream_RC4_128 | CBC_Fresh(_) ->
                let cmkb, b = split b macKeySize in
                let smkb, b = split b macKeySize in
                let cekb, b = split b encKeySize in
                let sekb, b = split b encKeySize in
                let ck = (cmkb @| cekb) in
                let sk = (smkb @| sekb) in
                match ci.role with
                | Client ->
                    (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState ck,
                     StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState sk)
                | Server ->
                    (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState sk,
                     StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState ck)
            | CBC_Stale(alg) ->
                let ivsize = blockSize alg
                let cmkb, b = split b macKeySize in
                let smkb, b = split b macKeySize in
                let cekb, b = split b encKeySize in
                let sekb, b = split b encKeySize in
                let civb, sivb = split b ivsize in
                let ck = (cmkb @| cekb @| civb) in
                let sk = (smkb @| sekb @| sivb) in
                match ci.role with
                | Client ->
                    (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState ck,
                     StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState sk)
                | Server ->
                    (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState sk,
                     StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState ck)
        | _ -> unexpectedError "[keyGen] invoked on unsupported ciphersuite"

let makeVerifyData e role (ms:masterSecret) data =
  let si = epochSI(e) in
  let pv = si.protocol_version in
  let tag =
    match pv with
    | SSL_3p0           ->
        match role with
        | Client -> ssl_verifyData ms.bytes ssl_sender_client data
        | Server -> ssl_verifyData ms.bytes ssl_sender_server data
    | TLS_1p0 | TLS_1p1 ->
        match role with
        | Client -> tls_verifyData ms.bytes tls_sender_client data
        | Server -> tls_verifyData ms.bytes tls_sender_server data
    | TLS_1p2           ->
        let cs = si.cipher_suite in
        match role with
        | Client -> tls12VerifyData cs ms.bytes tls_sender_client data
        | Server -> tls12VerifyData cs ms.bytes tls_sender_server data
  #if ideal
  if honest si && strong si then
    finish_log := (si, tag, data)::!finish_log;
  #endif
  tag

let checkVerifyData e role ms log expected =
  let computed = makeVerifyData e role ms log
  equalBytes expected computed
  //#begin-ideal2
  #if ideal
  && // ideally, we return "false" when concrete
     // verification suceeeds but shouldn't according to the log
    let si = epochSI(e)
    safe e = false || (exists (fun el -> el=(si, expected, log)) !finish_log)
  //#end-ideal2
  #endif

let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
  match algs with
  | SA_RSA -> ssl_certificate_verify ms.bytes log MD5 @| ssl_certificate_verify ms.bytes log SHA
  | SA_DSA -> ssl_certificate_verify ms.bytes log SHA
  | _      -> unexpectedError "[ssl_certificate_verify] invoked on a wrong signature algorithm"

//#begin-coerce
let coerce (si:SessionInfo) b =
  #if ideal
  corrupted := si::!corrupted;
  #endif
  {bytes = b}
//#end-coerce
