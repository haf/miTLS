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

module CoreDH
open Bytes
(* ------------------------------------------------------------------------ *)
open System
open System.IO
open System.Text

open Org.BouncyCastle.Math
open Org.BouncyCastle.Security
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Utilities.IO.Pem
open Org.BouncyCastle.Asn1

(* ------------------------------------------------------------------------ *)
open CoreKeys

type skey = dhskey
type pkey = dhpkey

(* ------------------------------------------------------------------------ *)
let check_element (pbytes:bytes) (ebytes:bytes) =
    let pm1 = (new BigInteger(1,cbytes pbytes)).Subtract(BigInteger.One) in
    let e = new BigInteger(1,cbytes ebytes) in
    // check e in [2,p-1)
    ((e.CompareTo BigInteger.One) > 0) && ((e.CompareTo pm1) < 0)

(* ------------------------------------------------------------------------ *)
let gen_params () : dhparams =
    let random    = new SecureRandom() in
    let generator = new DHParametersGenerator() in
        generator.Init(1024, 80, random);
        let dhparams = generator.GenerateParameters() in
            { p = abytes (dhparams.P.ToByteArrayUnsigned());
              g = abytes (dhparams.G.ToByteArrayUnsigned()); }

(* ------------------------------------------------------------------------ *)
let gen_key (dh : dhparams) : skey * pkey =
    let dhparams = new DHParameters(new BigInteger(1, cbytes dh.p), new BigInteger(1, cbytes dh.g)) in
    let kparams  = new DHKeyGenerationParameters(new SecureRandom(), dhparams) in
    let kgen     = new DHKeyPairGenerator() in
        kgen.Init(kparams);
        let kpair = kgen.GenerateKeyPair() in
        let pkey  = (kpair.Public  :?> DHPublicKeyParameters ) in
        let skey  = (kpair.Private :?> DHPrivateKeyParameters) in
            ((abytes (skey.X.ToByteArrayUnsigned()), dh), (abytes (pkey.Y.ToByteArrayUnsigned()), dh))

(* ------------------------------------------------------------------------ *)
let agreement (dh : dhparams) (x : dhsbytes) (y : dhpbytes) : bytes =
    let x = new BigInteger(1, cbytes x) in
    let y = new BigInteger(1, cbytes y) in
    let p = new BigInteger(1, cbytes dh.p) in
        abytes (y.ModPow(x, p).ToByteArrayUnsigned())

(* ------------------------------------------------------------------------ *)
let PEM_DH_PARAMETERS_HEADER = "DH PARAMETERS"

let dhparams = "-----BEGIN DH PARAMETERS-----
MIIBBwKBgQCctCTvtt225fYth0f8s/s+3K27xVqzrDf4fvgrmLj7OGSoJlghp6pQ
8nEGD+8jRQWak9JMrz1OlQ00YnaYuHb9QyO92O5ZVoBTXcZ07EUycXCWPmJaXUm2
X9XGm5BGhfncqc354ixfrt/+oi9h1PscSfiJvjC0rAjtfcE5xVHMNwKBgE/5q47Z
JhFd6fQhUYfiVyNuolP6z0FCZKrmLa9C6UgPLVTfEEOiW6KsCFh5uiCNYcINDZnb
lInlgrHXG2tlv4/QNCXmXBQeUBkVM+4EXOl2ZciEvFv2zAlkUig/CUcLGo/OwsJV
c8o7MMjRcCH7fDi4BIAzdEKdDYB7uEqnGJgn
-----END DH PARAMETERS-----"

(* ------------------------------------------------------------------------ *)
let save_params (stream : Stream) (dh : dhparams) =
    let writer    = new PemWriter(new StreamWriter(stream)) in
    let derparams = new DerSequence([| new DerInteger(new BigInteger(1, cbytes dh.p)) :> Asn1Encodable;
                                       new DerInteger(new BigInteger(1, cbytes dh.g)) :> Asn1Encodable|])
                        :> Asn1Encodable in

    writer.WriteObject(new PemObject(PEM_DH_PARAMETERS_HEADER, derparams.GetDerEncoded()));
    writer.Writer.Flush()

let save_params_to_file (file : string) (dh : dhparams) =
    let filestream = new FileStream(file, FileMode.Create, FileAccess.Write) in

    try
        try
            save_params filestream dh
            true
        finally
            filestream.Close()
    with _ ->
        false

(* ------------------------------------------------------------------------ *)
let load_params (stream : Stream) : dhparams =
    let reader = new PemReader(new StreamReader(stream)) in
    let obj    = reader.ReadPemObject() in

    if obj.Type <> PEM_DH_PARAMETERS_HEADER then
        raise (new SecurityUtilityException());

    let obj = DerSequence.GetInstance(Asn1Object.FromByteArray(obj.Content)) in

    if obj.Count <> 2 then
        raise (new SecurityUtilityException());

    { p = abytes (DerInteger.GetInstance(obj.Item(0)).PositiveValue.ToByteArrayUnsigned()) ;
      g = abytes (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned()) }

let load_params_from_file (file : string) : dhparams option =
    let filestream = new FileStream(file, FileMode.Open, FileAccess.Read) in

    try
        try
            Some (load_params filestream)
        finally
            filestream.Close()
    with _ -> None

(* ------------------------------------------------------------------------ *)
let load_default_params () =
    try
        load_params (new MemoryStream(Encoding.ASCII.GetBytes(dhparams), false))
    with _ ->
        failwith "cannot load default DH parameters"
