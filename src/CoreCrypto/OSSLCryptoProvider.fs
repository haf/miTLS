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
namespace OSSLCryptoProvider

open System
open CryptoProvider

(* ------------------------------------------------------------------------ *)
type OSSLMessageDigest (engine : OpenSSL.MD) =
    static member TypeOfName (name : string) =
        let name = name.ToUpperInvariant () in
            try
                Some (Enum.Parse(typeof<OpenSSL.MDType>, name, false) :?> OpenSSL.MDType)
            with :? ArgumentException -> None

    interface MessageDigest with
        member self.Name =
            engine.Name

        member self.Digest (b : byte[]) =
            engine.Update(b)
            engine.Final()

(* ------------------------------------------------------------------------ *)
type OSSLBlockCipher (engine : OpenSSL.CIPHER) =
    interface BlockCipher with
        member self.Name =
            engine.Name

        member self.BlockSize =
            engine.BlockSize

        member self.Direction =
            match engine.ForEncryption with
            | true  -> ForEncryption
            | false -> ForDecryption

        member self.Process (b : byte[]) =
            engine.Process(b)

(* ------------------------------------------------------------------------ *)
type OSSLStreamCipher (engine : OpenSSL.SCIPHER) =
    interface StreamCipher with
        member self.Name =
            engine.Name

        member self.Direction =
            match engine.ForEncryption with
            | true  -> ForEncryption
            | false -> ForDecryption

        member self.Process (b : byte[]) =
            engine.Process(b)

(* ------------------------------------------------------------------------ *)
type OSSLHMac (engine : OpenSSL.HMAC) =
    interface HMac with
        member self.Name =
            engine.Name

        member self.Process(b : byte[]) =
            engine.HMac(b)

(* ------------------------------------------------------------------------ *)
type OSSLProvider () =
    do
        fprintfn stderr "Using lib eay version %10x" (OpenSSL.Core.SSLeay())

    interface Provider with
        member self.MessageDigest (name : string) =
            Option.map
                (fun type_ -> new OSSLMessageDigest (new OpenSSL.MD(type_)) :> MessageDigest)
                (OSSLMessageDigest.TypeOfName (name))

        member self.BlockCipher (d : direction) (c : cipher) (m : mode option) (k : key) =
            let mode, iv =
                match m with
                | None          -> (OpenSSL.CMode.ECB, None)
                | Some (CBC iv) -> (OpenSSL.CMode.CBC, Some iv)

            let type_ =
                match c with
                | DES3                          -> Some OpenSSL.CType.DES3
                | AES when k.Length = (128 / 8) -> Some OpenSSL.CType.AES128
                | AES when k.Length = (256 / 8) -> Some OpenSSL.CType.AES256
                | _                             -> None
            in

            try
                match type_ with
                | None       -> None
                | Some type_ ->
                    let engine = new OpenSSL.CIPHER (type_, mode, (d = ForEncryption)) in
                        engine.Key <- k;
                        iv |> Option.iter (fun iv -> engine.IV <- iv);
                        Some (new OSSLBlockCipher(engine) :> BlockCipher)

            with :? OpenSSL.EVPException -> None

        member self.StreamCipher (d : direction) (c : scipher) (k : key) =
            let type_ =
                match c with
                | RC4 -> OpenSSL.SType.RC4
            in

            try
                let engine = new OpenSSL.SCIPHER(type_, (d = ForEncryption)) in
                    engine.Key <- k;
                    Some (new OSSLStreamCipher(engine) :> StreamCipher)
            with :? OpenSSL.EVPException -> None

        member self.HMac (name : string) (k : key) =
            try
                let from_md (md : OpenSSL.MDType) =
                    let engine = OpenSSL.HMAC(md) in
                        engine.Key <- k;
                        new OSSLHMac(engine) :> HMac
                in
                    Option.map from_md (OSSLMessageDigest.TypeOfName (name))
            with :? OpenSSL.EVPException -> None
