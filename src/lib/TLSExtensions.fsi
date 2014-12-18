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

// Following types only used in handshake
type clientExtension
type serverExtension

// Client side
val prepareClientExtensions: config -> ConnectionInfo -> cVerifyData -> list<clientExtension>
val clientExtensionsBytes: list<clientExtension> -> bytes
val parseServerExtensions: bytes -> Result<(list<serverExtension>)>
val negotiateClientExtensions: list<clientExtension> -> list<serverExtension> -> bool -> cipherSuite -> Result<negotiatedExtensions>

// Server side
val parseClientExtensions: bytes -> cipherSuites -> Result<(list<clientExtension>)>
val negotiateServerExtensions: list<clientExtension> -> config -> cipherSuite -> (cVerifyData * sVerifyData) -> bool -> (list<serverExtension> * negotiatedExtensions)
val serverExtensionsBytes: list<serverExtension> -> bytes

// Extension-specific
val checkClientRenegotiationInfoExtension: config -> list<clientExtension> -> cVerifyData -> bool
val checkServerRenegotiationInfoExtension: config -> list<serverExtension> -> cVerifyData -> sVerifyData -> bool

#if TLSExt_sessionHash
val hasExtendedMS: negotiatedExtensions -> bool
#endif

#if TLSExt_extendedPadding
val hasExtendedPadding: id -> bool
#endif

val sigHashAlgBytes: Sig.alg -> bytes
val parseSigHashAlg: bytes -> Result<Sig.alg>
val sigHashAlgListBytes: list<Sig.alg> -> bytes
val parseSigHashAlgList: bytes -> Result<list<Sig.alg>>
val default_sigHashAlg: ProtocolVersion -> cipherSuite -> list<Sig.alg>
val sigHashAlg_contains: list<Sig.alg> -> Sig.alg -> bool
val cert_type_list_to_SigHashAlg: list<certType> -> ProtocolVersion -> list<Sig.alg>
val cert_type_list_to_SigAlg: list<certType> -> list<sigAlg>
val sigHashAlg_bySigList: list<Sig.alg> -> list<sigAlg> -> list<Sig.alg>
