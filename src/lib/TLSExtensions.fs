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

module TLSExtensions

open Bytes
open Error
open TLSConstants

type extensionType =
    | HExt_renegotiation_info

let extensionTypeBytes hExt =
    match hExt with
    | HExt_renegotiation_info -> [|0xFFuy; 0x01uy|]

let parseExtensionType b =
    match b with
    | [|0xFFuy; 0x01uy|] -> correct(HExt_renegotiation_info)
    | _                  -> let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_decode_error, reason)

let isExtensionType et (ext:extensionType * bytes) =
    let et' = fst(ext) in
    et = et'

let extensionBytes extType data =
    let extTBytes = extensionTypeBytes extType in
    let payload = vlbytes 2 data in
    extTBytes @| payload

let consExt (e:extensionType * bytes) l = e :: l

let rec parseExtensionList data list =
    match length data with
    | 0 -> correct (list)
    | x when x < 4 ->
        (* This is a parsing error, or a malformed extension *)
        Error (AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ ->
        let (extTypeBytes,rem) = Bytes.split data 2 in
        match vlsplit 2 rem with
            | Error(x,y) -> Error (x,y) (* Parsing error *)
            | Correct (res) ->
                let (payload,rem) = res in
                match parseExtensionType extTypeBytes with
                | Error(x,y) ->
                    (* Unknown extension, skip it *)
                    parseExtensionList rem list
                | Correct(extType) ->
                    let thisExt = (extType,payload) in
                    let list = consExt thisExt list in
                    parseExtensionList rem list

(* Renegotiation Info extension -- RFC 5746 *)
let renegotiationInfoExtensionBytes verifyData =
    let payload = vlbytes 1 verifyData in
    extensionBytes HExt_renegotiation_info payload

let parseRenegotiationInfoExtension payload =
    if length payload > 0 then
        vlparse 1 payload
    else
        let reason = perror __SOURCE_FILE__ __LINE__ "" in
        Error(AD_decode_error,reason)

(* Top-level extension handling *)
let extensionsBytes safeRenegoEnabled verifyData =
    if safeRenegoEnabled then
        let renInfo = renegotiationInfoExtensionBytes verifyData in
        vlbytes 2 renInfo
    else
        (* We are sending no extensions at all *)
        [||]

let parseExtensions data =
    match length data with
    | 0 -> let el = [] in correct (el)
    | 1 -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ ->
        match vlparse 2 data with
        | Error(x,y)    -> Error(x,y)
        | Correct(exts) ->
            match parseExtensionList exts [] with
            | Error(x,y) -> Error(x,y)
            | Correct(extList) ->
                (* Check there is at most one renegotiation_info extension *)

                let ren_ext_list = Bytes.filter (isExtensionType HExt_renegotiation_info) extList in
                if listLength ren_ext_list > 1 then
                    Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Same extension received more than once")
                else
                    correct(ren_ext_list)

let check_reneg_info payload expected =
    // We also check there were no more data in this extension.
    match parseRenegotiationInfoExtension payload with
    | Error(x,y)     -> false
    | Correct (recv) -> equalBytes recv expected

let checkClientRenegotiationInfoExtension (ren_ext_list:(extensionType * bytes) list) ch_cipher_suites expected =
    let has_SCSV = contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV ch_cipher_suites in
    if equalBytes expected [||]
    then
        (* First handshake *)
        if listLength ren_ext_list = 0
        then has_SCSV
            (* either client gave SCSV and no extension; this is OK for first handshake *)
            (* or the client doesn't support this extension and we fail *)
        else
            let ren_ext = listHead ren_ext_list in
            let (extType,payload) = ren_ext in
            check_reneg_info payload expected
    else
        (* Not first handshake *)
        if has_SCSV || (listLength ren_ext_list = 0) then false
        else
            let ren_ext = listHead ren_ext_list in
            let (extType,payload) = ren_ext in
            check_reneg_info payload expected

let inspect_ServerHello_extensions (extList:(extensionType * bytes) list) expected =

    (* We expect to find exactly one extension *)
    match listLength extList with
    | 0 -> Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Not enough extensions given")
    | x when x <> 1 -> Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Too many extensions given")
    | _ ->
        let (extType,payload) = listHead extList in
        match extType with
        | HExt_renegotiation_info ->
            (* Check its content *)
            if check_reneg_info payload expected then
                let unitVal = () in
                correct (unitVal)
            else
                (* RFC 5746, sec 3.4: send a handshake failure alert *)
                Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Wrong renegotiation information")

(* SignatureAndHashAlgorithm parsing functions *)
let sigHashAlgBytes alg =
    // pre: we're in TLS 1.2
    let (sign,hash) = alg in
    let signB = sigAlgBytes sign in
    let hashB = hashAlgBytes hash in
    hashB @| signB

let parseSigHashAlg b =
    let (hashB,signB) = Bytes.split b 1 in
    match parseSigAlg signB with
    | Error(x,y) -> Error(x,y)
    | Correct(sign) ->
        match parseHashAlg hashB with
        | Error(x,y) -> Error(x,y)
        | Correct(hash) -> correct(sign,hash)

let rec sigHashAlgListBytes algL =
    match algL with
    | [] -> [||]
    | h::t ->
        let oneItem = sigHashAlgBytes h in
        oneItem @| sigHashAlgListBytes t

let rec parseSigHashAlgList_int b : (Sig.alg list Result)=
    if length b = 0 then correct([])
    elif length b = 1 then Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else
        let (thisB,remB) = Bytes.split b 2 in
        match parseSigHashAlg thisB with
        | Error(x,y) -> Error(x,y)
        | Correct(this) ->
            match parseSigHashAlgList_int remB with
            | Error(x,y) -> Error(x,y)
            | Correct(rem) -> correct(this :: rem)

let parseSigHashAlgList b =
    match vlparse 2 b with
    | Error(x,y) -> Error(x,y)
    | Correct(b) -> parseSigHashAlgList_int b

let default_sigHashAlg_fromSig pv sigAlg=
    match sigAlg with
    | SA_RSA ->
        match pv with
        | TLS_1p2 -> [(SA_RSA, SHA)]
        | TLS_1p0 | TLS_1p1 | SSL_3p0 -> [(SA_RSA,MD5SHA1)]
        //| SSL_3p0 -> [(SA_RSA,NULL)]
    | SA_DSA ->
        [(SA_DSA,SHA)]
        //match pv with
        //| TLS_1p0| TLS_1p1 | TLS_1p2 -> [(SA_DSA, SHA)]
        //| SSL_3p0 -> [(SA_DSA,NULL)]
    | _ -> unexpectedError "[default_sigHashAlg_fromSig] invoked on an invalid signature algorithm"

let default_sigHashAlg pv cs =
    default_sigHashAlg_fromSig pv (sigAlg_of_ciphersuite cs)

let sigHashAlg_contains (algList:Sig.alg list) (alg:Sig.alg) =
    Bytes.exists (fun a -> a = alg) algList

let sigHashAlg_bySigList (algList:Sig.alg list) (sigAlgList:sigAlg list) =
    Bytes.choose (fun alg -> let (sigA,_) = alg in if (Bytes.exists (fun a -> a = sigA) sigAlgList) then Some(alg) else None) algList

let cert_type_to_SigHashAlg ct pv =
    match ct with
    | TLSConstants.DSA_fixed_dh | TLSConstants.DSA_sign -> default_sigHashAlg_fromSig pv SA_DSA
    | TLSConstants.RSA_fixed_dh | TLSConstants.RSA_sign -> default_sigHashAlg_fromSig pv SA_RSA

let rec cert_type_list_to_SigHashAlg ctl pv =

    match ctl with
    | [] -> []
    | h::t -> (cert_type_to_SigHashAlg h pv) @ (cert_type_list_to_SigHashAlg t pv)

let cert_type_to_SigAlg ct =
    match ct with
    | TLSConstants.DSA_fixed_dh | TLSConstants.DSA_sign -> SA_DSA
    | TLSConstants.RSA_fixed_dh | TLSConstants.RSA_sign -> SA_RSA

let rec cert_type_list_to_SigAlg ctl =

    match ctl with
    | [] -> []
    | h::t -> (cert_type_to_SigAlg h) :: (cert_type_list_to_SigAlg t)
