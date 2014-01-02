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

module Cert

(* ------------------------------------------------------------------------ *)
open System.Text
open System.Collections.Generic
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

open Bytes
open TLSConstants
open Error

(* ------------------------------------------------------------------------ *)
type hint = string
type cert = bytes

type chain = cert list
type sign_cert = (chain * Sig.alg * Sig.skey) option
type enc_cert  = (chain * RSAKey.sk) option

(* ------------------------------------------------------------------------ *)
let OID_RSAEncryption           = "1.2.840.113549.1.1.1"
let OID_MD5WithRSAEncryption    = "1.2.840.113549.1.1.4"
let OID_SHAWithRSAEncryption    = "1.2.840.113549.1.1.5"
let OID_SHA256WithRSAEncryption = "1.2.840.113549.1.1.11"
let OID_DSASignatureKey         = "1.2.840.10040.4.1"
let OID_DSASignature            = "1.2.840.10040.4.3"

let oid_of_keyalg = function
| SA_RSA   -> OID_RSAEncryption
| SA_DSA   -> OID_DSASignatureKey
| SA_ECDSA -> Error.unexpectedError "SA_ECDSA"

(* ------------------------------------------------------------------------ *)
let x509_to_public_key (x509 : X509Certificate2) =
    match x509.GetKeyAlgorithm() with
    | x when x = OID_RSAEncryption ->
        try
            let pkey = (x509.PublicKey.Key :?> RSA).ExportParameters(false) in
                Some (CoreSig.PK_RSA (pkey.Modulus, pkey.Exponent))
        with :? CryptographicException -> None

    | x when x = OID_DSASignatureKey ->
        try
            let pkey = (x509.PublicKey.Key :?> DSA).ExportParameters(false) in
            let dsaparams : CoreKeys.dsaparams =
                { p = pkey.P; q = pkey.Q; g = pkey.G }
            in
                Some (CoreSig.PK_DSA (pkey.Y, dsaparams))
        with :? CryptographicException -> None

    | _ -> None

let x509_to_secret_key (x509 : X509Certificate2) =
    match x509.GetKeyAlgorithm() with
    | x when x = OID_RSAEncryption ->
        try
            let skey = (x509.PrivateKey :?> RSA).ExportParameters(true) in
                Some (CoreSig.SK_RSA (skey.Modulus, skey.D))
        with :? CryptographicException -> None

    | x when x = OID_DSASignatureKey ->
        try
            let skey = (x509.PrivateKey :?> DSA).ExportParameters(true) in
            let dsaparams : CoreKeys.dsaparams =
                { p = skey.P; q = skey.Q; g = skey.G }
            in
                Some (CoreSig.SK_DSA (skey.X, dsaparams))
        with :? CryptographicException -> None

    | _ -> None

(* ------------------------------------------------------------------------ *)
let x509_has_key_usage_flag strict flag (x509 : X509Certificate2) =
    try
        let kue =
            x509.Extensions
                |> Seq.cast
                |> Seq.find (fun (e : X509Extension) -> e.Oid.Value = "2.5.29.15") in
        let kue = kue :?> X509KeyUsageExtension in

            kue.KeyUsages.HasFlag(flag)

    with :? KeyNotFoundException ->
        not strict

(* ------------------------------------------------------------------------ *)
let x509_check_key_sig_alg (sigkeyalg : Sig.alg) (x509 : X509Certificate2) =
    match x509.SignatureAlgorithm with (* WARN: OID_MD5WithRSAEncryption is obsolete - removed *)
    | o when o.Value = OID_SHAWithRSAEncryption ->
         (* We are not strict, to comply with TLS < 1.2 *)
            sigkeyalg = (SA_RSA, MD5SHA1)
         || sigkeyalg = (SA_RSA, SHA    )
         || sigkeyalg = (SA_RSA, NULL   )
    | o when o.Value = OID_SHA256WithRSAEncryption ->
        sigkeyalg = (SA_RSA, SHA256)
    | o when o.Value = OID_DSASignature ->
        sigkeyalg = (SA_DSA, SHA)
    | _ -> false

let x509_check_key_sig_alg_one (sigkeyalgs : Sig.alg list) (x509 : X509Certificate2) =
    List.exists (fun a -> x509_check_key_sig_alg a x509) sigkeyalgs

(* ------------------------------------------------------------------------ *)
let x509_verify (x509 : X509Certificate2) =
    let chain = new X509Chain() in
        chain.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck;
        chain.Build(x509)

(* ------------------------------------------------------------------------ *)
let x509_chain (x509 : X509Certificate2) = (* FIX: Is certs. store must be opened ? *)
    let chain = new X509Chain() in
        chain.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck;
        ignore (chain.Build(x509));
        chain.ChainElements
            |> Seq.cast
            |> Seq.map (fun (ce : X509ChainElement) -> ce.Certificate)
            |> Seq.toList

(* ------------------------------------------------------------------------ *)
let x509_export_public (x509 : X509Certificate2) : bytes =
    x509.Export(X509ContentType.Cert)

(* ------------------------------------------------------------------------ *)
let x509_is_for_signing (x509 : X509Certificate2) =
       x509.Version >= 3
    && x509_has_key_usage_flag false X509KeyUsageFlags.DigitalSignature x509

let x509_is_for_key_encryption (x509 : X509Certificate2) =
    x509.Version >= 3
    && x509_has_key_usage_flag false X509KeyUsageFlags.KeyEncipherment x509

(* ------------------------------------------------------------------------ *)
let for_signing (sigkeyalgs : Sig.alg list) (h : hint) (algs : Sig.alg list) =
    let store = new X509Store(StoreName.My, StoreLocation.CurrentUser) in

    store.Open(OpenFlags.ReadOnly ||| OpenFlags.OpenExistingOnly)
    try
        try
            let (x509, ((siga, hasha) as alg)) =
                let pick_wrt_req_alg (x509 : X509Certificate2) =
                    let testalg ((asig, _) : Sig.alg) =
                        x509.GetKeyAlgorithm() = oid_of_keyalg asig
                    in

                    if x509.HasPrivateKey && x509_is_for_signing x509 then
                        match List.tryFind testalg algs with
                        | None     -> None
                        | Some alg -> Some (x509, alg)
                    else
                        None
                in
                    store.Certificates.Find(X509FindType.FindBySubjectName, h, false)
                        |> Seq.cast
                        |> Seq.filter (fun (x509 : X509Certificate2) -> x509_verify x509)
                        |> Seq.filter (x509_check_key_sig_alg_one sigkeyalgs)
                        |> Seq.pick pick_wrt_req_alg
            in
                match x509_to_secret_key x509 with
                | Some skey ->
                    let chain = x509_chain x509 in

                    if Seq.forall (x509_check_key_sig_alg_one sigkeyalgs) chain then
                        Some (chain |> List.map x509_export_public, alg, Sig.create_skey hasha skey)
                    else
                        None
                | None -> None
        with :? KeyNotFoundException -> None
    finally
        store.Close()

(* ------------------------------------------------------------------------ *)
let for_key_encryption (sigkeyalgs : Sig.alg list) (h : hint) =
    let store = new X509Store(StoreName.My, StoreLocation.CurrentUser) in

    store.Open(OpenFlags.ReadOnly ||| OpenFlags.OpenExistingOnly)
    try
        try
            let x509 =
                store.Certificates.Find(X509FindType.FindBySubjectName, h, false)
                    |> Seq.cast
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509_verify x509)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.HasPrivateKey)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509_is_for_key_encryption x509)
                    |> Seq.filter (fun (x509 : X509Certificate2) -> x509.GetKeyAlgorithm() = OID_RSAEncryption)
                    |> Seq.filter (x509_check_key_sig_alg_one sigkeyalgs)
                    |> Seq.pick   Some
            in
                match x509_to_secret_key x509 with
                | Some (CoreSig.SK_RSA(sm, se)) ->
                    let chain = x509_chain x509 in

                    if Seq.forall (x509_check_key_sig_alg_one sigkeyalgs) chain then
                        Some (chain |> List.map x509_export_public, RSAKey.create_rsaskey (sm, se))
                    else
                        None
                | _ -> None
        with
        | :? KeyNotFoundException -> None
    finally
        store.Close()

(* ------------------------------------------------------------------------ *)
let is_for_signing (c : cert) =
    try
        x509_is_for_signing (new X509Certificate2(c))
    with :? CryptographicException -> false

let is_for_key_encryption (c : cert) =
    try
        x509_is_for_key_encryption (new X509Certificate2(c))
    with :? CryptographicException -> false

(* ------------------------------------------------------------------------ *)
let is_chain_for_signing (chain : chain) =
    match chain with [] -> false| c :: _ -> is_for_signing c

let is_chain_for_key_encryption (chain : chain) =
    match chain with [] -> false| c :: _ -> is_for_key_encryption c

(* ------------------------------------------------------------------------ *)
let get_public_signing_key (c : cert) ((siga, hasha) as a : Sig.alg) : Sig.pkey Result =
    try
        let x509 = new X509Certificate2(c) in
            if x509_is_for_signing x509 then
                match siga, x509_to_public_key x509 with
                | SA_RSA, Some (CoreSig.PK_RSA (sm, se) as k) -> Correct (Sig.create_pkey hasha k)
                | SA_DSA, Some (CoreSig.PK_DSA (y, p  ) as k) -> Correct (Sig.create_pkey hasha k)
                | _ -> Error(AD_unsupported_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate uses unknown signature algorithm or key")
            else
                Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate is not for signing")
    with :? CryptographicException -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let get_public_encryption_key (c : cert) : RSAKey.pk Result =
    try
        let x509 = new X509Certificate2(c) in
            if x509_is_for_key_encryption x509 then
                match x509_to_public_key x509 with
                | Some (CoreSig.PK_RSA(pm, pe)) -> Correct (RSAKey.create_rsapkey (pm, pe))
                | _ -> Error(AD_unsupported_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate uses unknown key")
            else
                Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate is not for key encipherment")
    with :? CryptographicException -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(* ------------------------------------------------------------------------ *)
let get_chain_public_signing_key (chain : chain) a =
    match chain with
    | []     -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "This is likely a bug, please report it")
    | c :: _ -> get_public_signing_key c a

let get_chain_public_encryption_key (chain : chain) =
    match chain with
    | []     -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "This is likely a bug, please report it")
    | c :: _ -> get_public_encryption_key c

(* ------------------------------------------------------------------------ *)
let get_chain_key_algorithm (chain : chain) =
    match chain with
    | []     -> None
    | c :: _ ->
        try
            let x509 = new X509Certificate2(c) in
                match x509.GetKeyAlgorithm () with
                | x when x = OID_RSAEncryption   -> Some SA_RSA
                | x when x = OID_DSASignatureKey -> Some SA_DSA
                | _ -> None
        with :? CryptographicException -> None

(* ------------------------------------------------------------------------ *)
let rec validate_x509_chain (c : X509Certificate2) (issuers : X509Certificate2 list) =
    try
        let chain = new X509Chain () in
            chain.ChainPolicy.ExtraStore.AddRange(List.toArray issuers);
            chain.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck;

            if not (chain.Build(c)) then
                false
            else
                let eq_thumbprint (c1 : X509Certificate2) (c2 : X509Certificate2) =
                    c1.Thumbprint = c2.Thumbprint
                in

                let certschain =
                    chain.ChainElements
                        |> Seq.cast
                        |> (Seq.map (fun (ce : X509ChainElement) -> ce.Certificate))
                        |> Seq.toList
                in
                    (certschain.Length >= issuers.Length)
                    && Seq.forall2 eq_thumbprint certschain issuers

    with :? CryptographicException -> false

(* ------------------------------------------------------------------------ *)
let validate_cert_chain (sigkeyalgs : Sig.alg list) (chain : chain) =
    match chain with
    | []           -> false
    | c :: issuers ->
        try
            let c       = new X509Certificate2(c) in
            let issuers = List.map (fun (c : cert) -> new X509Certificate2(c)) chain in
                Seq.forall (x509_check_key_sig_alg_one sigkeyalgs) (c :: issuers)
                && validate_x509_chain c issuers

        with :? CryptographicException ->
            false

(* ------------------------------------------------------------------------ *)
let get_hint (chain : chain) =
    let chain = List.map (fun (c : cert) -> new X509Certificate2(c)) chain in

    match chain with
    | []     -> None
    | c :: _ -> Some (c.GetNameInfo (X509NameType.SimpleName, false)) (* FIX *)

(* ---- TLS-specific encoding ---- *)
let consCertificateBytes c a =
    let cert = vlbytes 3 c in
    cert @| a

let certificateListBytes certs =
    let unfolded = Bytes.foldBack consCertificateBytes certs [||] in
    vlbytes 3 unfolded

let rec parseCertificateList toProcess list =
    if equalBytes toProcess [||] then
        correct(list)
    else
        if length toProcess >= 3 then
            match vlsplit 3 toProcess with
            | Error(x,y) -> Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ y)
            | Correct (res) ->
                let (nextCert,toProcess) = res in
                let list = list @ [nextCert] in
                parseCertificateList toProcess list
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
