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

module TLSConstants

open Bytes
open Error

(* Not abstract, but meant to be used only by crypto modules and CipherSuites *)

type PreProtocolVersion =
    | SSL_3p0
    | TLS_1p0
    | TLS_1p1
    | TLS_1p2
type ProtocolVersion = PreProtocolVersion

type kexAlg =
    | RSA
    | DH_DSS
    | DH_RSA
    | DHE_DSS
    | DHE_RSA
    | DH_anon

type blockCipher =
    | TDES_EDE
    | AES_128
    | AES_256

type encAlg =
    | CBC_Stale of blockCipher
    | CBC_Fresh of blockCipher
    | Stream_RC4_128

type hashAlg =
    | NULL
    | MD5SHA1
    | MD5
    | SHA
    | SHA256
    | SHA384

type macAlg =
    | MA_HMAC of hashAlg
    | MA_SSLKHASH of hashAlg

type sigAlg =
  | SA_RSA
  | SA_DSA
  | SA_ECDSA

type aeadAlg =
    | AES_128_GCM
    | AES_256_GCM

type authencAlg =
    | MACOnly of macAlg
    | MtE of encAlg * macAlg
    | AEAD of aeadAlg * macAlg

val sigAlgBytes: sigAlg -> bytes
val parseSigAlg: bytes -> sigAlg Result
val hashAlgBytes: hashAlg -> bytes
val parseHashAlg: bytes -> hashAlg Result

val encKeySize: encAlg -> nat
val blockSize: blockCipher -> nat
val aeadKeySize: aeadAlg -> nat
val aeadIVSize: aeadAlg -> nat
val macKeySize: macAlg -> nat
val macSize: macAlg -> nat

(* SSL/TLS Constants *)
val ssl_pad1_md5: bytes
val ssl_pad2_md5: bytes
val ssl_pad1_sha1: bytes
val ssl_pad2_sha1: bytes
val ssl_sender_client: bytes
val ssl_sender_server: bytes
val tls_sender_client: string
val tls_sender_server: string
val tls_master_secret: string
val tls_key_expansion: string

type cipherSuite

type cipherSuites = cipherSuite list

type Compression =
    | NullCompression

val versionBytes: ProtocolVersion -> bytes
val parseVersion: bytes -> ProtocolVersion Result
val minPV: ProtocolVersion -> ProtocolVersion -> ProtocolVersion
val geqPV: ProtocolVersion -> ProtocolVersion -> bool
val somePV: ProtocolVersion -> ProtocolVersion option

val nullCipherSuite: cipherSuite
val isNullCipherSuite: cipherSuite -> bool

val isAnonCipherSuite: cipherSuite -> bool
val isDHCipherSuite: cipherSuite -> bool
val isDHECipherSuite: cipherSuite -> bool
val isRSACipherSuite: cipherSuite -> bool
val contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV: cipherSuites -> bool
val verifyDataLen_of_ciphersuite: cipherSuite -> nat
val prfMacAlg_of_ciphersuite: cipherSuite -> macAlg
val verifyDataHashAlg_of_ciphersuite: cipherSuite -> hashAlg

val authencAlg_of_ciphersuite: cipherSuite -> ProtocolVersion -> authencAlg
val macAlg_of_ciphersuite: cipherSuite -> ProtocolVersion -> macAlg
val encAlg_of_ciphersuite: cipherSuite -> ProtocolVersion -> encAlg
val sigAlg_of_ciphersuite: cipherSuite -> sigAlg

val compressionBytes: Compression -> bytes
val compressionMethodsBytes: Compression list -> bytes
val parseCompression: bytes -> Compression Result
val parseCompressions: bytes -> Compression list

val cipherSuiteBytes: cipherSuite -> bytes
val parseCipherSuite: bytes -> cipherSuite Result
val parseCipherSuites: bytes -> cipherSuites Result
val cipherSuitesBytes: cipherSuites -> bytes

val getKeyExtensionLength: ProtocolVersion -> cipherSuite -> nat

(* Not for verification, just to run the implementation *)

type cipherSuiteName =
    | TLS_NULL_WITH_NULL_NULL

    | TLS_RSA_WITH_NULL_MD5
    | TLS_RSA_WITH_NULL_SHA
    | TLS_RSA_WITH_NULL_SHA256
    | TLS_RSA_WITH_RC4_128_MD5
    | TLS_RSA_WITH_RC4_128_SHA
    | TLS_RSA_WITH_3DES_EDE_CBC_SHA
    | TLS_RSA_WITH_AES_128_CBC_SHA
    | TLS_RSA_WITH_AES_256_CBC_SHA
    | TLS_RSA_WITH_AES_128_CBC_SHA256
    | TLS_RSA_WITH_AES_256_CBC_SHA256

    | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    | TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    | TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256

    | TLS_DH_anon_WITH_RC4_128_MD5
    | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
    | TLS_DH_anon_WITH_AES_128_CBC_SHA
    | TLS_DH_anon_WITH_AES_256_CBC_SHA
    | TLS_DH_anon_WITH_AES_128_CBC_SHA256
    | TLS_DH_anon_WITH_AES_256_CBC_SHA256

val cipherSuites_of_nameList: cipherSuiteName list -> cipherSuites

(* val split_at_most: bytes -> nat -> (bytes * bytes) *)

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data

type ContentType = preContentType
val bytes_of_seq: nat -> bytes
val seq_of_bytes: bytes -> nat

val ctBytes: ContentType -> bytes
val parseCT: bytes -> ContentType Result
val CTtoString: ContentType -> string

val vlbytes: nat -> bytes -> bytes
val vlsplit: nat -> bytes -> (bytes * bytes) Result
val vlparse: nat -> bytes -> bytes Result

//val splitList: bytes -> nat list -> bytes list

type certType =
    | RSA_sign
    | DSA_sign
    | RSA_fixed_dh
    | DSA_fixed_dh

val certTypeBytes: certType -> bytes
val parseCertType: bytes -> certType Result
val certificateTypeListBytes: certType list -> bytes
val parseCertificateTypeList: bytes -> certType list Result
val defaultCertTypes: bool -> cipherSuite -> certType list
val distinguishedNameListBytes: string list -> bytes
val parseDistinguishedNameList: bytes -> string list -> string list Result
