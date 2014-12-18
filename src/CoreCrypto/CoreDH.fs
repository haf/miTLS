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
open Error

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

(* ------------------------------------------------------------------------ *)
let check_params dhdb minSize (pbytes:bytes) (gbytes:bytes) =
    match DHDB.select dhdb (pbytes, gbytes) with
    | None -> // unknown group
        let p = new BigInteger(1, cbytes pbytes) in
        let g = new BigInteger(1, cbytes gbytes) in
        // check g in [2,p-2]
        let pm1 = p.Subtract(BigInteger.One)
        if ((g.CompareTo BigInteger.One) > 0) && ((g.CompareTo pm1) < 0) then
            // check if p is a safe prime, i.e. p = 2*q + 1 with prime q
            let q = pm1.Divide(BigInteger.Two)
            if p.IsProbablePrime(80) && q.IsProbablePrime(80) then
                let (minPl,minQl) = minSize in
                if p.BitLength < minPl || q.BitLength < minQl then
                    Error(perror __SOURCE_FILE__ __LINE__ "Subgroup too small")
                else
                    let qbytes = abytes (q.ToByteArrayUnsigned())
                    let dhdb = DHDB.insert dhdb (pbytes, gbytes) (qbytes, true) in
                    correct (dhdb,{dhp = pbytes; dhg = gbytes; dhq = qbytes; safe_prime = true})
            else
                Error (perror __SOURCE_FILE__ __LINE__ "Group with unknown order")
        else
            Error (perror __SOURCE_FILE__ __LINE__ "Group with small order")
    | Some(qbytes,safe_prime) -> // known group
        let p = new BigInteger(1, cbytes pbytes) in
        let q = new BigInteger(1, cbytes qbytes) in
        let (minPl,minQl) = minSize in
        if p.BitLength < minPl || q.BitLength < minQl then
            Error(perror __SOURCE_FILE__ __LINE__ "Subgroup too small")
        else
            correct (dhdb,{dhp = pbytes; dhg = gbytes ; dhq = qbytes ; safe_prime = safe_prime})

let check_element dhp (ebytes:bytes) =
    let p   = new BigInteger(1, cbytes dhp.dhp)
    let e   = new BigInteger(1, cbytes ebytes)
    let pm1 = p.Subtract(BigInteger.One)
    // check e in [2,p-2]
    if ((e.CompareTo BigInteger.One) > 0) && ((e.CompareTo pm1) < 0) then
        if dhp.safe_prime then
            true
        else
            let q = new BigInteger(1, cbytes dhp.dhq)
            let r = e.ModPow(q, p)
            // For OpenSSL-generated parameters order(g) = 2q, so e^q mod p = p-1
            r.Equals(BigInteger.One) || r.Equals(pm1)
    else
        false

(* ------------------------------------------------------------------------ *)
let gen_key_int dhparams =
    let kparams  = new DHKeyGenerationParameters(new SecureRandom(), dhparams) in
    let kgen     = new DHKeyPairGenerator() in
    kgen.Init(kparams);
    let kpair = kgen.GenerateKeyPair() in
    let pkey  = (kpair.Public  :?> DHPublicKeyParameters ) in
    let skey  = (kpair.Private :?> DHPrivateKeyParameters) in
    (abytes (skey.X.ToByteArrayUnsigned()), abytes (pkey.Y.ToByteArrayUnsigned()))

let gen_key dhp: dhskey * dhpkey =

    let dhparams = new DHParameters(new BigInteger(1, cbytes dhp.dhp), new BigInteger(1, cbytes dhp.dhg), new BigInteger(1, cbytes dhp.dhq)) in
    gen_key_int dhparams

let gen_key_pg p g =
    let dhparams = new DHParameters(new BigInteger(1, cbytes p), new BigInteger(1, cbytes g)) in
    gen_key_int dhparams

(* ------------------------------------------------------------------------ *)
let agreement p (x : dhskey) (y : dhpkey) : bytes =
    let x = new BigInteger(1, cbytes x) in
    let y = new BigInteger(1, cbytes y) in
    let p = new BigInteger(1, cbytes p) in
        abytes (y.ModPow(x, p).ToByteArrayUnsigned())

(* ------------------------------------------------------------------------ *)
let PEM_DH_PARAMETERS_HEADER = "DH PARAMETERS"

(* ------------------------------------------------------------------------ *)
let load_params (stream : Stream) : bytes*bytes =
    let reader = new PemReader(new StreamReader(stream)) in
    let obj    = reader.ReadPemObject() in

    if obj.Type <> PEM_DH_PARAMETERS_HEADER then
        raise (new SecurityUtilityException(sprintf "Wrong PEM header. Got %s" obj.Type))
    else
    let obj = DerSequence.GetInstance(Asn1Object.FromByteArray(obj.Content)) in

    if obj.Count <> 2 then
        raise (new SecurityUtilityException(sprintf "Unexpected number of DH parameters. Got %d" obj.Count))
    else
    (abytes (DerInteger.GetInstance(obj.Item(0)).PositiveValue.ToByteArrayUnsigned()),
     abytes (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned()))

(* ------------------------------------------------------------------------ *)
let load_params_from_file (file : string) : bytes * bytes =
    let filestream = new FileStream(file, FileMode.Open, FileAccess.Read) in
    try
        load_params filestream
    finally
        filestream.Close()

(* ------------------------------------------------------------------------ *)
let load_default_params pem_file dhdb minSize =
    let p,g = load_params_from_file pem_file in
    match check_params dhdb minSize p g with
    | Error(x) -> raise (new SecurityUtilityException(x))
    | Correct(res) -> res
