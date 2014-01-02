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

// Following types only used in handshake
type clientExtension
type serverExtension

// Client side
val clientExtensionsBytes: clientExtension list -> bytes
val prepareClientExtensions: config -> ConnectionInfo -> cVerifyData -> cVerifyData option -> clientExtension list
val parseServerExtensions: bytes -> (serverExtension list) Result
val negotiateClientExtensions: clientExtension list -> serverExtension list -> bool -> negotiatedExtensions Result

// Server side
val serverExtensionsBytes: serverExtension list -> bytes
val negotiateServerExtensions: clientExtension list -> config -> ConnectionInfo -> (cVerifyData * sVerifyData) -> (cVerifyData * sVerifyData) option -> (serverExtension list * negotiatedExtensions)
val parseClientExtensions: bytes -> cipherSuites -> (clientExtension list) Result

// Extension-specific
val checkClientRenegotiationInfoExtension: config -> clientExtension list -> cVerifyData -> bool
val checkServerRenegotiationInfoExtension: config -> serverExtension list -> cVerifyData -> sVerifyData -> bool

// type extensionType
//
// val extensionsBytes: bool -> bytes -> bytes
// val parseExtensions: bytes -> (extensionType * bytes) list Result
// val inspect_ServerHello_extensions: (extensionType * bytes) list -> bytes -> unit Result
// val checkClientRenegotiationInfoExtension: (extensionType * bytes) list -> TLSConstants.cipherSuites -> bytes -> bool

val sigHashAlgBytes: Sig.alg -> bytes
val parseSigHashAlg: bytes -> Sig.alg Result
val sigHashAlgListBytes: Sig.alg list -> bytes
val parseSigHashAlgList: bytes -> Sig.alg list Result
val default_sigHashAlg: ProtocolVersion -> cipherSuite -> Sig.alg list
val sigHashAlg_contains: Sig.alg list -> Sig.alg -> bool
val cert_type_list_to_SigHashAlg: certType list -> ProtocolVersion -> Sig.alg list
val cert_type_list_to_SigAlg: certType list -> sigAlg list
val sigHashAlg_bySigList: Sig.alg list -> sigAlg list -> Sig.alg list
