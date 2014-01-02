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
open TLSError
open TLSConstants
open TLSInfo

type extensionType =
    | HExt_renegotiation_info
    | HExt_extended_padding

let extensionTypeBytes hExt =
    match hExt with
    | HExt_renegotiation_info -> abyte2 (0xFFuy, 0x01uy)
    | HExt_extended_padding -> abyte2 (0xBBuy, 0x8Fuy)

let parseExtensionType b =
    match cbyte2 b with
    | (0xFFuy, 0x01uy) -> correct(HExt_renegotiation_info)
    | (0xBBuy, 0x8Fuy) -> correct(HExt_extended_padding)
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
let extensionsBytes cfg verifyData peerExtPad =
    let renInfo =
        if cfg.safe_renegotiation then
            renegotiationInfoExtensionBytes verifyData
        else
            empty_bytes
    let extPad =
        if cfg.extended_padding && peerExtPad then
            extensionBytes HExt_extended_padding empty_bytes
        else
            empty_bytes
    if equalBytes renInfo empty_bytes && equalBytes extPad empty_bytes then
        (* We are sending no extensions at all *)
        empty_bytes
    else
        vlbytes 2 (renInfo @| extPad)

let rec checkExtCount extList =
    match extList with
    | [] -> correct()
    | h::t ->
        let (extType,_) = h in
        let count = List.filter (isExtensionType extType) t in
        if List.listLength count > 0 then
            Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Same extension received more than once")
        else
            checkExtCount t

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
                (* Check there is at most one extension per type*)
                match checkExtCount extList with
                | Error(x,y) -> Error(x,y)
                | Correct() -> correct(extList)

let check_reneg_info payload expected =
    // We also check there were no more data in this extension.
    match parseRenegotiationInfoExtension payload with
    | Error(x,y)     -> Error(x,y)
    | Correct (recv) ->
        if equalBytes recv expected then
            correct()
        else
            (* RFC 5746, sec 3.4: send a handshake failure alert *)
            Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Wrong renegotiation information")

let inspect_ClientHello_extensions cfg (extList:(extensionType * bytes) list) ch_cipher_suites expected =
    (* Safe renegotiation *)
    let safe_renego =
        if cfg.safe_renegotiation then
            let renExt = List.filter (isExtensionType HExt_renegotiation_info) extList in
            let count = List.listLength renExt in
            let has_SCSV = contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV ch_cipher_suites in
            if equalBytes expected empty_bytes then
                (* First handshake *)
                match (count,has_SCSV) with
                | (0,true) ->
                    (* the client gave SCSV and no extension; this is OK for first handshake *)
                    correct()
                | (0,false) ->
                    (* the client doesn't support this extension: we report error *)
                    Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Client does not support the requested safe renegotiation extension")
                | (_,_) ->
                    let ren_ext = List.listHead renExt in
                    let (extType,payload) = ren_ext in
                    check_reneg_info payload expected
            else
                (* Not first handshake *)
                if has_SCSV || (count = 0) then
                    Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Client provided wrong information for safe renegotiation extension")
                else
                    let ren_ext = List.listHead renExt in
                    let (extType,payload) = ren_ext in
                    check_reneg_info payload expected
        else
            (* Ignore client provided extension *)
            correct()

    match safe_renego with
    | Error(x,y) -> Error(x,y)
    | Correct() ->
    (* Extended record padding *)
        if cfg.extended_padding then
            let count = List.filter (isExtensionType HExt_extended_padding) extList in
            let count = List.listLength count in
            if count = 0 then
                correct(false)
            else
                correct(true)
        else
            (* Ignore client provided extension *)
            correct(false)

let inspect_ServerHello_extensions cfg (extList:(extensionType * bytes) list) expected =
    let unitVal = () in
    let renegOutcome =
        let renExt = List.filter (isExtensionType HExt_renegotiation_info) extList in
        let count = List.listLength renExt in
        if cfg.safe_renegotiation then
            match count with
            | 1 ->
                let (_,payload) = List.listHead renExt in
                check_reneg_info payload expected
            | _ -> (* Extension not provided by server *)
                Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Server did not provide required safe renegotiation extension")
        else
            (* We, as a client, did not send a safe renegotiation extension,
               check there is no such extension in server reply *)
            if count > 0 then
                Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Renegotiation info extension provided by server, but not sent by the client")
            else
                correct (unitVal)
    match renegOutcome with
    | Error(x,y) -> Error(x,y)
    | Correct() ->
    (* Extended padding *)
    let count = List.filter (isExtensionType HExt_extended_padding) extList in
    let count = List.listLength count in
    if cfg.extended_padding then
        if count = 0 then
            correct(false)
        else
            correct(true)
    else
        (* We, as a client, did not send an extended padding extension,
            check there is no such extension in server reply *)
        if count > 0 then
            Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Extended padding extension provided by server, but not sent by the client")
        else
            correct(false)

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
    | [] -> empty_bytes
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
    | _ -> unexpected "[default_sigHashAlg_fromSig] invoked on an invalid signature algorithm"

let default_sigHashAlg pv cs =
    default_sigHashAlg_fromSig pv (sigAlg_of_ciphersuite cs)

let sigHashAlg_contains (algList:Sig.alg list) (alg:Sig.alg) =
    List.exists (fun a -> a = alg) algList

let sigHashAlg_bySigList (algList:Sig.alg list) (sigAlgList:sigAlg list):Sig.alg list =
    List.choose (fun alg -> let (sigA,_) = alg in if (List.exists (fun a -> a = sigA) sigAlgList) then Some(alg) else None) algList

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
