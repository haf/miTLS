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

module RSA

open Bytes
open Error
open TLSConstants
open TLSInfo

#if ideal
// We maintain a log to look up ideal_pms values using fake_pms values.
let log = ref []
#endif

let encrypt key pv pms =
    //#begin-ideal1
    #if ideal

    let v = if RSAKey.honest key && not (CRE.corrupt (CRE.RSA_pms pms)) then
              let fake_pms = (versionBytes pv) @|random 46
              log := (fake_pms,pms)::!log
              fake_pms
            else
              CRE.leakRSA key pv pms
    //#end-ideal1
    #else
    let v = CRE.leakRSA key pv pms
    #endif
    CoreACiphers.encrypt_pkcs1 (RSAKey.repr_of_rsapkey key) v

//#begin-decrypt_int
let decrypt_int dk si cv cvCheck encPMS =
  (*@ Security measures described in RFC 5246, section 7.4.7.1 *)
  (*@ 1. Generate random data, 46 bytes, for PMS except client version *)
  let fakepms = random 46 in
  (*@ 2. Decrypt the message to recover plaintext *)
  let expected = versionBytes cv in
  match CoreACiphers.decrypt_pkcs1 (RSAKey.repr_of_rsaskey dk) encPMS with
    | Some pms when length pms = 48 ->
        let (clVB,postPMS) = split pms 2 in
        match si.protocol_version with
          | TLS_1p1 | TLS_1p2 ->
              (*@ 3. If new TLS version, just go on with client version and true pms.
                    This corresponds to a check of the client version number, but we'll fail later. *)
              expected @| postPMS

          | SSL_3p0 | TLS_1p0 ->
              (*@ 3. If check disabled, use client provided PMS, otherwise use our version number *)
              if cvCheck
              then expected @| postPMS
              else pms
    | _  ->
        (*@ 3. in case of decryption of length error, continue with fake PMS *)
        expected @| fakepms
//#end-decrypt_int

let decrypt dk si cv check_client_version_in_pms_for_old_tls encPMS =
    match Cert.get_chain_public_encryption_key si.serverID with
    | Error(x,y) -> unexpectedError (perror __SOURCE_FILE__ __LINE__ "The server identity should contain a valid certificate")
    | Correct(pk) ->
        let pmsb = decrypt_int dk si cv check_client_version_in_pms_for_old_tls encPMS in
        //#begin-ideal2
        #if ideal

        match tryFind (fun el -> fst el=pmsb) !log  with
            Some(_,ideal_pms) -> ideal_pms
           |None -> CRE.coerceRSA pk cv pmsb
        //#end-ideal2
        #else
        CRE.coerceRSA pk cv pmsb
        #endif
