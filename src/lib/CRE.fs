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

module CRE

open Bytes
open TLSConstants
open TLSInfo
open TLSPRF

type rsarepr = bytes
type rsapms = {rsapms: rsarepr}
type dhpms = {dhpms: DHGroup.elt}

#if ideal
type pms = RSA_pms of rsapms | DHE_pms of dhpms

type pred = GeneratedRSAPMS of RSAKey.pk * ProtocolVersion * rsapms

// We maintain two log:
// - a log of honest pms values
// - a log for looking up good ms values using their pms values values

let honest_log = ref []
let honest pms = exists (fun el -> el=pms) !honest_log

let corrupt pms = not(honest pms)

let log = ref []
#endif

let genRSA (pk:RSAKey.pk) (vc:TLSConstants.ProtocolVersion) : rsapms =
    let verBytes = TLSConstants.versionBytes vc in
    let rnd = Nonce.mkRandom 46 in
    let pms = verBytes @| rnd in
    let pms = {rsapms = pms}
    #if ideal
    if RSAKey.honest pk then honest_log := RSA_pms(pms)::!honest_log
    // event keeping track of honestly-generated PMSs
    Pi.assume (GeneratedRSAPMS(pk,vc,pms));
    #endif
    pms

let coerceRSA (pk:RSAKey.pk) (pv:ProtocolVersion) b = {rsapms = b}
let leakRSA (pk:RSAKey.pk) (pv:ProtocolVersion) pms = pms.rsapms

let sampleDH p g (gx:DHGroup.elt) (gy:DHGroup.elt) =
    let gz = DHGroup.genElement p g in
    let pms = {dhpms = gz}
    #if ideal
    honest_log := DHE_pms(pms)::!honest_log
    #endif
    pms

let coerceDH (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (gy:DHGroup.elt) b = {dhpms = b}

// internal
let prfMS sinfo pmsBytes: PRF.masterSecret =
    let pv = sinfo.protocol_version in
    let cs = sinfo.cipher_suite in
    let data = sinfo.init_crand @| sinfo.init_srand in
    let res = prf pv cs pmsBytes tls_master_secret data 48 in
    PRF.coerce sinfo res

let prfSmoothRSA si (pv:ProtocolVersion) pms =
    #if ideal

    if not(corrupt (RSA_pms(pms)))
    then match tryFind (fun el -> fst el = RSA_pms(pms)) !log with
             Some(_,ms) -> ms
           | None ->
                 let ms=PRF.sample si
                 log := (RSA_pms(pms),ms)::!log
                 ms
    else prfMS si pms.rsapms
    #else
    prfMS si pms.rsapms
    #endif

let prfSmoothDHE si (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (gy:DHGroup.elt) (pms:dhpms) =
    //#begin-ideal
    #if ideal

    if not(corrupt (DHE_pms(pms)))
    then match tryFind (fun el -> fst el = DHE_pms(pms)) !log  with
             Some(_,ms) -> ms
           | None ->
                 let ms=PRF.sample si
                 log := (DHE_pms(pms),ms)::!log;
                 ms
    else prfMS si pms.dhpms
    //#end-ideal
    #else
    prfMS si pms.dhpms
    #endif
