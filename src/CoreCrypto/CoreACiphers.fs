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

module CoreACiphers
open Bytes

open Org.BouncyCastle.Math
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Encodings
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Parameters

type modulus  = bytes
type exponent = bytes

type sk = RSASKey of CoreKeys.rsaskey
type pk = RSAPKey of CoreKeys.rsapkey

type plain = bytes
type ctxt  = bytes

let encrypt_pkcs1 (RSAPKey (m, e)) (plain : plain) =
    let m, e   = new BigInteger(1, cbytes m),
                 new BigInteger(1, cbytes e) in
    let engine = new RsaEngine() in
    let engine = new Pkcs1Encoding(engine) in

    engine.Init(true, new RsaKeyParameters(false, m, e))
    abytes (engine.ProcessBlock(cbytes plain, 0, length plain))

let decrypt_pkcs1 (RSASKey (m, e)) (ctxt : ctxt) =
    let m, e   = new BigInteger(1, cbytes m),
                 new BigInteger(1, cbytes e) in
    let engine = new RsaEngine() in
    let engine = new Pkcs1Encoding(engine) in

    try
        engine.Init(false, new RsaKeyParameters(true, m, e))
        Some (abytes (engine.ProcessBlock(cbytes ctxt, 0, length ctxt)))
    with :? InvalidCipherTextException ->
        None
