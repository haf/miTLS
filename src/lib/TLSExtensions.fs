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

module TLSExtensions

open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo

type clientExtension =
    | CE_renegotiation_info of cVerifyData
//    | CE_server_name of list<Cert.hint>
    | CE_extended_ms
    | CE_extended_padding

let sameClientExt a b =
    match a,b with
    | CE_renegotiation_info (_), CE_renegotiation_info (_) -> true
    | CE_extended_ms, CE_extended_ms -> true
    | CE_extended_padding, CE_extended_padding -> true
    | _,_ -> false

type serverExtension =
    | SE_renegotiation_info of cVerifyData * sVerifyData
//    | SE_server_name of Cert.hint
    | SE_extended_ms
    | SE_extended_padding

let sameServerExt a b =
    match a,b with
    | SE_renegotiation_info (_,_), SE_renegotiation_info (_,_) -> true
    | SE_extended_ms, SE_extended_ms -> true
    | SE_extended_padding, SE_extended_padding -> true
    | _,_ -> false

let sameServerClientExt a b =
    match a,b with
    | SE_renegotiation_info (_,_), CE_renegotiation_info (_) -> true
    | SE_extended_ms, CE_extended_ms -> true
    | SE_extended_padding, CE_extended_padding -> true
    | _,_ -> false

let clientExtensionHeaderBytes ext =
    match ext with
    | CE_renegotiation_info(_) -> abyte2 (0xFFuy, 0x01uy)
//    | CE_server_name (_)     -> abyte2 (0x00uy, 0x00uy)
    | CE_extended_ms           -> abyte2 (0x00uy, 0x17uy)
    | CE_extended_padding      -> abyte2 (0xBBuy, 0x8Fuy)

let clientExtensionPayloadBytes ext =
    match ext with
    | CE_renegotiation_info(cvd) -> vlbytes 1 cvd
    | CE_extended_ms -> empty_bytes
    | CE_extended_padding -> empty_bytes

let clientExtensionBytes ext =
    let head = clientExtensionHeaderBytes ext in
    let payload = clientExtensionPayloadBytes ext in
    let payload = vlbytes 2 payload in
    head @| payload

let clientExtensionsBytes extL =
    let extBL = List.map (fun e -> clientExtensionBytes e) extL in
    let extB = List.fold (fun s l -> s @| l) empty_bytes extBL in
    if equalBytes extB empty_bytes then
        empty_bytes
    else
        vlbytes 2 extB

let parseClientExtension head payload =
    match cbyte2 head with
    | (0xFFuy, 0x01uy) -> // renegotiation info
        (match vlparse 1 payload with
        | Error (x,y) -> Some(Error(x,y))
        | Correct(cvd) ->
            let res = CE_renegotiation_info (cvd) in
            let res = correct res in
            Some(res))
#if TLSExt_sessionHash
    | (0x00uy, 0x17uy) -> // extended_ms
        if equalBytes payload empty_bytes then
            Some(correct (CE_extended_ms))
        else
            Some(Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid data for extended master secret extension"))
#endif
#if TLSExt_extendedPadding
    | (0xBBuy, 0x8Fuy) -> // extended_padding
        if equalBytes payload empty_bytes then
            Some(correct (CE_extended_padding))
        else
            Some(Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid data for extended padding extension"))
#endif
    | (_,_) -> None

let addOnceClient ext extList =
    if List.exists (sameClientExt ext) extList then
        Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Same extension received more than once")
    else
        let res = ext::extList in
        correct(res)

let rec parseClientExtensionList ext extList =
    match length ext with
    | 0 -> correct (extList)
    | x when x < 4 ->
        (* This is a parsing error, or a malformed extension *)
        Error (AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ ->
        let (extTypeBytes,rem) = Bytes.split ext 2 in
        match vlsplit 2 rem with
            | Error(x,y) -> Error (x,y) (* Parsing error *)
            | Correct (res) ->
                let (payload,rem) = res in
                match parseClientExtension extTypeBytes payload with
                | None ->
                    (* Unknown extension, skip it *)
                    parseClientExtensionList rem extList
                | Some(res) ->
                    match res with
                    | Error(x,y) -> Error(x,y)
                    | Correct(ce) ->
                        match addOnceClient ce extList with
                        | Error(x,y) -> Error(x,y)
                        | Correct(extList) -> parseClientExtensionList rem extList

let rec parseClientSCSVs ch_ciphers extL =
    if contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV ch_ciphers then
        addOnceClient (CE_renegotiation_info(empty_bytes)) extL
    else
        correct(extL)

let parseClientExtensions data ch_ciphers =
    match length data with
    | 0 -> parseClientSCSVs ch_ciphers []
    | 1 -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ ->
        match vlparse 2 data with
        | Error(x,y)    -> Error(x,y)
        | Correct(exts) ->
            match parseClientExtensionList exts [] with
            | Error(x,y) -> Error(x,y)
            | Correct(extL) -> parseClientSCSVs ch_ciphers extL

let prepareClientExtensions (cfg:config) (conn:ConnectionInfo) renegoCVD =
    (* Always send supported extensions. The configuration options will influence how strict the tests will be *)
    let res = [CE_renegotiation_info(renegoCVD)] in
#if TLSExt_sessionHash
    let res = CE_extended_ms :: res in
#endif
#if TLSExt_extendedPadding
    let res = CE_extended_padding :: res in
#endif
    res

let serverToNegotiatedExtension cExtL (resuming:bool) cs res sExt : Result<negotiatedExtensions>=
    match res with
    | Error(x,y) -> Error(x,y)
    | Correct(l) ->
        if List.exists (sameServerClientExt sExt) cExtL then
            match sExt with
            | SE_renegotiation_info (_,_) -> correct (l)
            | SE_extended_ms ->
                if resuming then
                    correct(l)
                else
                    correct(NE_extended_ms::l)
            | SE_extended_padding ->
                if resuming then
                    Error(AD_handshake_failure,perror __SOURCE_FILE__ __LINE__ "Server provided extended padding in a resuming handshake")
                else
                    if isOnlyMACCipherSuite cs then
                        Error(AD_handshake_failure,perror __SOURCE_FILE__ __LINE__ "Server provided extended padding for a MAC only ciphersuite")
                    else
                        correct(NE_extended_padding::l)
        else
            Error(AD_handshake_failure,perror __SOURCE_FILE__ __LINE__ "Server provided an extension not given by the client")

let negotiateClientExtensions (cExtL:list<clientExtension>) (sExtL:list<serverExtension>) (resuming:bool) cs =
    match Collections.List.fold (serverToNegotiatedExtension cExtL resuming cs) (correct []) sExtL with
    | Error(x,y) -> Error(x,y)
    | Correct(l) ->
        // Client-side specific extension negotiation
        // Nothing for now
        correct(l)

let serverExtensionHeaderBytes ext =
    match ext with
    | SE_renegotiation_info (_,_) -> abyte2 (0xFFuy, 0x01uy)
 //   | SE_server_name (_)        -> abyte2 (0x00uy, 0x00uy)
    | SE_extended_ms              -> abyte2 (0x00uy, 0x17uy)
    | SE_extended_padding         -> abyte2 (0xBBuy, 0x8Fuy)

let serverExtensionPayloadBytes ext =
    match ext with
    | SE_renegotiation_info (cvd,svd) ->
        let p = cvd @| svd in
        vlbytes 1 p
    | SE_extended_ms -> empty_bytes
    | SE_extended_padding -> empty_bytes

let serverExtensionBytes ext =
    let head = serverExtensionHeaderBytes ext in
    let payload = serverExtensionPayloadBytes ext in
    let payload = vlbytes 2 payload in
    head @| payload

let serverExtensionsBytes extL =
    let extBL = List.map (fun e -> serverExtensionBytes e) extL in
    let extB = List.fold (fun s l -> s @| l) empty_bytes extBL in
    if equalBytes extB empty_bytes then
        empty_bytes
    else
        vlbytes 2 extB

let parseServerExtension head payload =
    match cbyte2 head with
    | (0xFFuy, 0x01uy) -> // renegotiation info
        (match vlparse 1 payload with
        | Error (x,y) -> Error(x,y)
        | Correct(vd) ->
            let vdL = length vd in
            let (cvd,svd) = split vd (vdL/2) in
            let res = SE_renegotiation_info (cvd,svd) in
            correct(res))
    | (0x00uy, 0x17uy) -> // extended master secret
        if equalBytes payload empty_bytes then
            correct(SE_extended_ms)
        else
            Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid data for extended master secret extension")
    | (0xBBuy, 0x8Fuy) -> // extended padding
        if equalBytes payload empty_bytes then
            correct(SE_extended_padding)
        else
            Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid data for extended padding extension")
    | (_,_) ->
        // A server can never send an extension the client doesn't support
        Error(AD_unsupported_extension, perror __SOURCE_FILE__ __LINE__ "Server provided an unsupported extesion")

let addOnceServer ext extList =
    if List.exists (sameServerExt ext) extList then
        Error(AD_handshake_failure, perror __SOURCE_FILE__ __LINE__ "Same extension received more than once")
    else
        let res = ext::extList in
        correct(res)

let rec parseServerExtensionList ext extList =
    match length ext with
    | 0 -> correct (extList)
    | x when x < 4 ->
        (* This is a parsing error, or a malformed extension *)
        Error (AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ ->
        let (extTypeBytes,rem) = Bytes.split ext 2 in
        match vlsplit 2 rem with
            | Error(x,y) -> Error (x,y) (* Parsing error *)
            | Correct (res) ->
                let (payload,rem) = res in
                match parseServerExtension extTypeBytes payload with
                | Error(x,y) -> Error(x,y)
                | Correct(ce) ->
                    match addOnceServer ce extList with
                    | Error(x,y) -> Error(x,y)
                    | Correct(extList) -> parseServerExtensionList rem extList

let parseServerExtensions data =
    match length data with
    | 0 -> let el = [] in correct (el)
    | 1 -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | _ ->
        match vlparse 2 data with
        | Error(x,y)    -> Error(x,y)
        | Correct(exts) -> parseServerExtensionList exts []

let ClientToServerExtension (cfg:config) cs ((renegoCVD:cVerifyData),(renegoSVD:sVerifyData)) (resuming:bool) cExt : option<serverExtension>=
    match cExt with
    | CE_renegotiation_info (_) -> Some (SE_renegotiation_info (renegoCVD,renegoSVD))

    | CE_extended_ms -> Some(SE_extended_ms)
    | CE_extended_padding ->
        if resuming then
            None
        else
            if isOnlyMACCipherSuite cs then
                None
            else
                Some(SE_extended_padding)

let ClientToNegotiatedExtension (cfg:config) cs ((cvd:cVerifyData),(svd:sVerifyData)) (resuming:bool) cExt : option<negotiatedExtension> =
    match cExt with
    | CE_renegotiation_info (_) -> None
    | CE_extended_ms ->
        if resuming then
            None
        else
            Some(NE_extended_ms)
    | CE_extended_padding ->
        if resuming then
            None
        else
            if isOnlyMACCipherSuite cs then
                None
            else
                Some(NE_extended_padding)

let negotiateServerExtensions cExtL cfg cs (cvd,svd) resuming =
    let server = List.choose (ClientToServerExtension cfg cs (cvd,svd) resuming) cExtL in
    let nego = List.choose (ClientToNegotiatedExtension cfg cs (cvd,svd) resuming) cExtL in
    (server,nego)

let isClientRenegotiationInfo e =
    match e with
    | CE_renegotiation_info(cvd) -> Some(cvd)
    | _ -> None

let checkClientRenegotiationInfoExtension config (cExtL: list<clientExtension>) cVerifyData =
    match List.tryPick isClientRenegotiationInfo cExtL with
    | None -> not (config.safe_renegotiation)
    | Some(payload) -> equalBytes payload cVerifyData

let isServerRenegotiationInfo e =
    match e with
    | SE_renegotiation_info (cvd,svd) -> Some((cvd,svd))
    | _ -> None

let checkServerRenegotiationInfoExtension config (sExtL: list<serverExtension>) cVerifyData sVerifyData =
    match List.tryPick isServerRenegotiationInfo sExtL with
    | None -> not (config.safe_renegotiation)
    | Some(x) ->
        let (cvd,svd) = x in
        equalBytes (cvd @| svd) (cVerifyData @| sVerifyData)

let isExtendedMS e =
    match e with
    | NE_extended_ms -> true
    | _ -> false

let hasExtendedMS extL =
    List.exists isExtendedMS extL

let isExtendedPadding e =
    match e with
    | NE_extended_padding -> true
    | _ -> false

let hasExtendedPadding id =
    List.exists isExtendedPadding id.ext

(* sigHashAlg parsing functions *)
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

let rec parseSigHashAlgList b : (Result<list<Sig.alg>>)=
    if length b = 0 then correct([])
    elif length b = 1 then Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else
        let (thisB,remB) = Bytes.split b 2 in
        match parseSigHashAlgList remB with
        | Error(x,y) -> Error(x,y)
        | Correct(rem) ->
            match parseSigHashAlg thisB with
            | Error(x,y) -> // skip this one
                correct(rem)
            | Correct(this) ->
                correct(this :: rem)

let default_sigHashAlg_fromSig pv sigAlg=
    match sigAlg with
    | SA_RSA ->
        (match pv with
        | TLS_1p2 -> [(SA_RSA, SHA)]
        | TLS_1p0 | TLS_1p1 | SSL_3p0 -> [(SA_RSA,MD5SHA1)])
        //| SSL_3p0 -> [(SA_RSA,NULL)]
    | SA_DSA ->
        [(SA_DSA,SHA)]
        //match pv with
        //| TLS_1p0| TLS_1p1 | TLS_1p2 -> [(SA_DSA, SHA)]
        //| SSL_3p0 -> [(SA_DSA,NULL)]
    | _ -> unexpected "[default_sigHashAlg_fromSig] invoked on an invalid signature algorithm"

let default_sigHashAlg pv cs =
    default_sigHashAlg_fromSig pv (sigAlg_of_ciphersuite cs)

let sigHashAlg_contains (algList:list<Sig.alg>) (alg:Sig.alg) =
    List.exists (fun a -> a = alg) algList

let sigHashAlg_bySigList (algList:list<Sig.alg>) (sigAlgList:list<sigAlg>):list<Sig.alg> =
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
