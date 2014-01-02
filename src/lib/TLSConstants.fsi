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
open TLSError

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

type sigHashAlg = sigAlg * hashAlg

type aeadAlg =
    | AES_128_GCM
    | AES_256_GCM

type aeAlg =
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
val aeadRecordIVSize: aeadAlg -> nat
val aeadTagSize: aeadAlg -> nat
val hashSize: hashAlg -> nat
val macKeySize: macAlg -> nat
val macSize: macAlg -> nat

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

type prflabel = bytes
val extract_label: prflabel
val kdf_label: prflabel

type prfAlg' =
  | CRE_SSL3_nested                   // MD5(SHA1(...)) for extraction and keygen
  | CRE_TLS_1p01 of prflabel          // MD5 xor SHA1
  | CRE_TLS_1p2 of prflabel * macAlg  // typically SHA256 but may depend on CS

type creAlg = prfAlg'
type prfAlg = ProtocolVersion * cipherSuite
type kdfAlg = prfAlg
type vdAlg = prfAlg

val verifyDataLen_of_ciphersuite: cipherSuite -> nat
val prfMacAlg_of_ciphersuite: cipherSuite -> macAlg
val verifyDataHashAlg_of_ciphersuite: cipherSuite -> hashAlg

val aeAlg: cipherSuite -> ProtocolVersion -> aeAlg
val macAlg_of_aeAlg: aeAlg -> macAlg
val encAlg_of_aeAlg: aeAlg -> encAlg
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

    | TLS_RSA_WITH_AES_128_GCM_SHA256
    | TLS_RSA_WITH_AES_256_GCM_SHA384
    | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    | TLS_DH_RSA_WITH_AES_128_GCM_SHA256
    | TLS_DH_RSA_WITH_AES_256_GCM_SHA384
    | TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
    | TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
    | TLS_DH_DSS_WITH_AES_128_GCM_SHA256
    | TLS_DH_DSS_WITH_AES_256_GCM_SHA384
    | TLS_DH_anon_WITH_AES_128_GCM_SHA256
    | TLS_DH_anon_WITH_AES_256_GCM_SHA384

val cipherSuites_of_nameList: cipherSuiteName list -> cipherSuites
val name_of_cipherSuite: cipherSuite -> cipherSuiteName Result

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
