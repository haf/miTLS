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

let gen_params () : dhparams =
    let random    = new SecureRandom() in
    let generator = new DHParametersGenerator() in
        generator.Init(1024, 80, random);
        let dhparams = generator.GenerateParameters() in
            { p = abytes (dhparams.P.ToByteArrayUnsigned());
              g = abytes (dhparams.G.ToByteArrayUnsigned());
              q = Some (abytes (dhparams.Q.ToByteArrayUnsigned())); }

(* ------------------------------------------------------------------------ *)
let gen_key (dh : dhparams) : skey * pkey =
    let dhparams =
        match dh.q with
          None    -> new DHParameters(new BigInteger(1, cbytes dh.p), new BigInteger(1, cbytes dh.g))
        | Some(q) -> new DHParameters(new BigInteger(1, cbytes dh.p), new BigInteger(1, cbytes dh.g), new BigInteger(1, cbytes q))
    in
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

// OpenSSL-generated 1024-bit modulus
// openssl dhparam -outform PEM -2 1024
// p = 2q+1, g = 2, order(g) = 2q
let default_params = "-----BEGIN DH PARAMETERS-----
MIIBCgKBgQDbGmBO+JPjdwlyfbFya+fYt2WJztweqhlmXf2gUbQU+wp0iJTITV3s
AHJYsGPtqgUy0pQuQOstJ07L7QTLweGf5jFIorpFE2tUe06uOlT/sF2utOo0mPfx
TeU9wO/ReYhRgTI2760oi8BYJC/HYgWv3/jRniS0EkLihqku1OQCWwIBAgKBgG2N
MCd8SfG7hLk+2Lk18+xbssTnbg9VDLMu/tAo2gp9hTpESmQmrvYAOSxYMfbVAplp
ShcgdZaTp2X2gmXg8M/zGKRRXSKJtao9p1cdKn/YLtdadRpMe/im8p7gd+i8xCjA
mRt31pRF4CwSF+OxAtfv/GjPEloJIXFDVJdqcgEt
-----END DH PARAMETERS-----"

// OpenSSL-generated 1024-bit modulus
// openssl dhparam -outform PEM -5 1024
// p = 2q+1, g = 5, order(g) = 2q
let openssl = "-----BEGIN DH PARAMETERS-----
MIIBCgKBgQC/llta3IgfxUZw7d/TLR1Ql8n61Kq9Ia/5y6+sVJPrAaW3koxMuOdk
1Ly9M2Mw5Y8sL5dgKf0wq9I90rit8V6gryWebcljWIMSCky//s/HvWwLQCk0Mlq6
c96o0QB6nD4Fr6IKNlTajJSBf5+k6+/JpnFDkqxCdYykLjcJzM5g6wIBBQKBgF/L
La1uRA/iozh27+mWjqhL5P1qVV6Q1/zl19YqSfWA0tvJRiZcc7JqXl6ZsZhyx5YX
y7AU/phV6R7pXFb4r1BXks825LGsQYkFJl//Z+PetgWgFJoZLV0571RogD1OHwLX
0QUbKm1GSkC/z9J19+TTOKHJViE6xlIXG4TmZzB1
-----END DH PARAMETERS-----"

// OpenSSL-generated 1024-bit modulus (not a safe prime)
// openssl dhparam -dsaparam -outform PEM 1024, converted to our custom format
// p = q*j + 1, q is a 160-bit prime, order(g) = q
let openssl_not_safe = "-----BEGIN DH PARAMETERS-----
MIIBHwKBgQDn8NH67s1WKGiou8QOdd6wX3DN0hAWkFyKrc6u943pYrFqaqVPRtnd
/l5aDJC9QsVe8CnVm48oK4Yk+/Owsc1xEs6gKz5LVItY897xDa12VAAtMofDxHJi
6X+BVuIZxuysW60fpeeDLd/Y0BFw5aAI0K4z08D1kR/yuyRzu62wQwKBgQC31lgI
UtXMD7eVdkjC9/+a5ZPFP9D/SVjkI7E/BZkvz8ESDC57l67IplT+g+twHfadDnXi
IyRbQ1p48KhEun+I9HziTlUft783ijUcX0fDKg7eRl/1ixyx3lAqes8Ag/xSKo66
UKftmjJgsSWfy76wlElxiwNUlEQib7h+TuxmqwIVANPqNA9w7g6THbmMcaS13ZLL
4AIL
-----END DH PARAMETERS-----"

// BouncyCastle-generated 1024-bit modulus
// p = 2q+1, random g, order(g) = q
let old_params = "-----BEGIN DH PARAMETERS-----
MIIBigKBgQCctCTvtt225fYth0f8s/s+3K27xVqzrDf4fvgrmLj7OGSoJlghp6pQ
8nEGD+8jRQWak9JMrz1OlQ00YnaYuHb9QyO92O5ZVoBTXcZ07EUycXCWPmJaXUm2
X9XGm5BGhfncqc354ixfrt/+oi9h1PscSfiJvjC0rAjtfcE5xVHMNwKBgE/5q47Z
JhFd6fQhUYfiVyNuolP6z0FCZKrmLa9C6UgPLVTfEEOiW6KsCFh5uiCNYcINDZnb
lInlgrHXG2tlv4/QNCXmXBQeUBkVM+4EXOl2ZciEvFv2zAlkUig/CUcLGo/OwsJV
c8o7MMjRcCH7fDi4BIAzdEKdDYB7uEqnGJgnAoGATloSd9tu23L7FsOj/ln9n25W
3eKtWdYb/D98FcxcfZwyVBMsENPVKHk4gwf3kaKCzUnpJleep0qGmjE7TFw7fqGR
3ux3LKtAKa7jOnYimTi4Sx8xLS6k2y/q403II0L87lTm/PEWL9dv/1EXsOp9jiT8
RN8YWlYEdr7gnOKo5hs=
-----END DH PARAMETERS-----"

(* ------------------------------------------------------------------------ *)
let save_params (stream : Stream) (dh : dhparams) =
    let writer    = new PemWriter(new StreamWriter(stream)) in
    let derparams =
        match dh.q with
          None ->
            new DerSequence([| new DerInteger(new BigInteger(1, cbytes dh.p)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes dh.g)) :> Asn1Encodable |])
            :> Asn1Encodable
        | Some(q) ->
            new DerSequence([| new DerInteger(new BigInteger(1, cbytes dh.p)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes dh.g)) :> Asn1Encodable;
                               new DerInteger(new BigInteger(1, cbytes q)) :> Asn1Encodable |])
            :> Asn1Encodable
        in
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

    if obj.Count < 2 then
        raise (new SecurityUtilityException());

    { p = abytes (DerInteger.GetInstance(obj.Item(0)).PositiveValue.ToByteArrayUnsigned()) ;
      g = abytes (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned()) ;
      q = if obj.Count > 2 then Some (abytes (DerInteger.GetInstance(obj.Item(2)).PositiveValue.ToByteArrayUnsigned())) else None }

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
        load_params (new MemoryStream(Encoding.ASCII.GetBytes(default_params), false))
    with _ ->
        failwith "cannot load default DH parameters"

(* ------------------------------------------------------------------------ *)
let check_element (pbytes:bytes) (gbytes:bytes) (ebytes:bytes) =
    let p   = new BigInteger(1, cbytes pbytes) in
    let e   = new BigInteger(1, cbytes ebytes) in
    let pm1 = p.Subtract(BigInteger.One) in
    // check e in [2,p-1)
    ((e.CompareTo BigInteger.One) > 0) && ((e.CompareTo pm1) < 0) &&
    // check that e is in a large subgroup
    let dhparams = load_default_params () in
    if (equalBytes dhparams.p pbytes && equalBytes dhparams.g gbytes) then
        // default parameters; q known and trusted
        match dhparams.q with
        | None -> Error.unexpected("DH.check_element: q not found in default DH parameters")
        | Some(qbytes) ->
            let q = new BigInteger(1, cbytes qbytes) in
            // This test is not necessary if p is a safe prime
            let r = e.ModPow(q, p) in
            // For OpenSSL-generated parameters order(g) = 2q, so e^q mod p = p-1
            (r.Equals(BigInteger.One) || r.Equals(pm1))
    else
       // check if p is a safe prime, i.e. p = 2q+1 with prime q
       let q = pm1.Divide(BigInteger.Two) in
       if p.IsProbablePrime(80) && q.IsProbablePrime(80) then true // p is a safe prime
       else

         true
