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

(* ------------------------------------------------------------------------ *)
namespace BCCryptoProvider

open CryptoProvider
open System

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Macs
open Org.BouncyCastle.Crypto.Modes
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Security

(* ------------------------------------------------------------------------ *)
type BCMessageDigest (engine : IDigest) =
    interface MessageDigest with
        member self.Name =
            engine.AlgorithmName

        member self.Digest (b : byte[]) =
            try
                engine.BlockUpdate(b, 0, b.Length)
                let output = Array.create (engine.GetDigestSize()) 0uy in
                    ignore (engine.DoFinal(output, 0));
                    output
            finally
                engine.Reset ()

(* ------------------------------------------------------------------------ *)
module BlockCipher =
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
        keyparams = fun k  -> new DesEdeParameters(k) :> ICipherParameters;
    }

(* ------------------------------------------------------------------------ *)
type BCBlockCipher (direction : direction, engine : IBlockCipher) =
    interface BlockCipher with
        member self.Name =
            engine.AlgorithmName

        member self.Direction =
            direction

        member self.BlockSize =
            engine.GetBlockSize ()

        member self.Process (b : byte[]) =
            let bsize = engine.GetBlockSize() in

            if (b.Length % bsize) <> 0 || b.Length = 0 then
                raise (new ArgumentException("invalid data size"));
            let output = Array.create (b.Length) 0uy in
                seq { 0 .. (b.Length / bsize - 1) }
                    |> (Seq.iter (fun i -> ignore (engine.ProcessBlock(b, i * bsize, output, i * bsize))));
                output

(* ------------------------------------------------------------------------ *)
type BCStreamCipher (direction : direction, engine : IStreamCipher) =
    interface StreamCipher with
        member self.Name =
            engine.AlgorithmName

        member self.Direction =
            direction

        member self.Process (b : byte[]) =
            let output = Array.zeroCreate b.Length in
                engine.ProcessBytes(b, 0, b.Length, output, 0);
                output

(* ------------------------------------------------------------------------ *)
type BCHMac (engine : Macs.HMac) =
    interface CryptoProvider.HMac with
        member self.Name =
            engine.AlgorithmName

        member self.Process (b : byte[]) =
            let output = Array.zeroCreate (engine.GetMacSize()) in

            try
                engine.BlockUpdate(b, 0, b.Length);
                ignore (engine.DoFinal(output, 0));
                output
            finally
                engine.Reset ()

(* ------------------------------------------------------------------------ *)
type BCProvider () =
    interface Provider with
        member self.MessageDigest (name : string) =
            try
                 let engine = DigestUtilities.GetDigest (name) in
                    Some (new BCMessageDigest (engine) :> MessageDigest)
            with :? SecurityUtilityException -> None

        member self.BlockCipher (d : direction) (c : cipher) (m : mode option) (k : key) =
            let icipher_of_cipher (cipher : cipher) =
                match cipher with
                | AES  -> BlockCipher.aes_icipher
                | DES3 -> BlockCipher.des3_icipher

            let icipher = icipher_of_cipher c in
            let icipher =
                match m with
                | None -> icipher
                | Some (CBC iv) ->
                    { create    = fun () -> new CbcBlockCipher(icipher.create ()) :> IBlockCipher;
                      keyparams = fun k  -> new ParametersWithIV(icipher.keyparams k, iv) :> ICipherParameters; }
            in
                let engine = icipher.create () in
                    engine.Init((d = ForEncryption), icipher.keyparams k);
                    Some (new BCBlockCipher (d, engine) :> BlockCipher)

        member self.StreamCipher (d : direction) (c : scipher) (k : key) =
            let engine =
                match c with
                | RC4 -> new RC4Engine () :> IStreamCipher
            in
                engine.Init ((d = ForEncryption), new KeyParameter (k));
                Some (new BCStreamCipher (d, engine) :> StreamCipher);

        member self.HMac (name : string) (k : key) =
            try
                let engine = DigestUtilities.GetDigest(name) in
                let engine = new Macs.HMac(engine) in
                    engine.Init(new KeyParameter(k));
                    Some (new BCHMac (engine) :> CryptoProvider.HMac)
            with :? SecurityUtilityException -> None
