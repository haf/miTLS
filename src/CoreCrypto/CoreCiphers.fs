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

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Modes

type direction = ForEncryption | ForDecryption

type engine = BCEngine of IBlockCipher * direction

exception InvalidBlockSize

let blocksize (BCEngine (e, _) : engine) =
    e.GetBlockSize()

let direction (BCEngine (_, direction)) =
    direction

let process_blocks (BCEngine (e, _) : engine) (b : byte[]) =
    let bsize = e.GetBlockSize() in

    if (b.Length % bsize) <> 0 || b.Length = 0 then
        raise InvalidBlockSize;
    let output = Array.create (b.Length) 0uy in
        seq { 0 .. (b.Length / bsize - 1) }
            |> (Seq.iter (fun i -> ignore (e.ProcessBlock(b, i * bsize, output, i * bsize))));
        output

type key = byte[]
type iv  = byte[]

type cipher = AES | DES3
type mode   = CBC of iv

type icipher = {
    create    : unit -> IBlockCipher;
    keyparams : key  -> ICipherParameters;
}

let aes_icipher = {
    create    = fun () -> new AesFastEngine() :> IBlockCipher;
    keyparams = fun k  -> new KeyParameter(k) :> ICipherParameters;
}

let des3_icipher = {
    create    = fun () -> new DesEdeEngine()      :> IBlockCipher;
    keyparams = fun k  -> new DesEdeParameters(k) :> ICipherParameters; // Check for known weak keys. Is it wanted?
}

let icipher_of_cipher (cipher : cipher) =
    match cipher with
    | AES  -> aes_icipher
    | DES3 -> des3_icipher

let engine (omode : mode option) (direction : direction) (cipher : cipher) (key : key) =
    let icipher = icipher_of_cipher cipher in
    let icipher =
        match omode with
        | None -> icipher
        | Some (CBC iv) ->
            { create    = fun () -> new CbcBlockCipher(icipher.create ()) :> IBlockCipher;
              keyparams = fun k  -> new ParametersWithIV(icipher.keyparams k, iv) :> ICipherParameters; }
    in
        let engine = icipher.create () in
            engine.Init((direction = ForEncryption), icipher.keyparams key);
            BCEngine (engine, direction)

let encrypt omode cipher key plain =
    let engine = engine omode ForEncryption cipher key in
        process_blocks engine plain

let decrypt omode cipher key encrypted =
    let engine = engine omode ForDecryption cipher key in
        process_blocks engine encrypted

let aes_cbc_encrypt key iv plain     = encrypt (Some (CBC iv)) AES key plain
let aes_cbc_decrypt key iv encrypted = decrypt (Some (CBC iv)) AES key encrypted

let des3_cbc_encrypt key iv plain     = encrypt (Some (CBC iv)) DES3 key plain
let des3_cbc_decrypt key iv encrypted = decrypt (Some (CBC iv)) DES3 key encrypted

type rc4engine = RC4Engine of RC4Engine

let rc4create (key : key) =
    let engine = new RC4Engine() in
        engine.Init(false (* ignored *), new KeyParameter(key));
        RC4Engine engine

let rc4process (RC4Engine engine) (input : byte[]) =
    let output = Array.create input.Length 0uy in
        engine.ProcessBytes(input, 0, input.Length, output, 0);
        output
