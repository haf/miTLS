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

module CoreCiphers

open CryptoProvider
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Parameters

type key = byte array
type iv  = byte array

let encrypt cipher omode key plain =
    let engine = CoreCrypto.BlockCipher ForEncryption cipher omode key in
        engine.Process (plain)

let decrypt cipher omode key encrypted =
    let engine = CoreCrypto.BlockCipher ForDecryption cipher omode key in
        engine.Process (encrypted)

let aes_cbc_encrypt key iv plain     = encrypt AES (Some (CBC iv)) key plain
let aes_cbc_decrypt key iv encrypted = decrypt AES (Some (CBC iv)) key encrypted

let des3_cbc_encrypt key iv plain     = encrypt DES3 (Some (CBC iv)) key plain
let des3_cbc_decrypt key iv encrypted = decrypt DES3 (Some (CBC iv)) key encrypted

type rc4engine = RC4Engine of StreamCipher

let rc4create (key : key) =
    let engine = CoreCrypto.StreamCipher ForEncryption (* ignored *) RC4 key in
        RC4Engine engine

let rc4process (RC4Engine engine) (input : byte[]) =
    engine.Process input
