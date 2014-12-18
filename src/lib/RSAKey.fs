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

module RSAKey

open Bytes

type pk = { pk : CoreACiphers.pk }
type sk = { sk : CoreACiphers.sk }

type pred = SK_PK of sk * pk

#if ideal

let honest_log = ref[]
let honest (pk:pk): bool = failwith "only used in ideal implementation, unverified"
let strong (pv:TLSConstants.ProtocolVersion): bool = failwith "only used in ideal implementation, unverified"
#endif

type modulus  = bytes
type exponent = bytes

let gen () : (pk * sk) =
    let csk, cpk = CoreACiphers.gen_key () in
    let sk = {sk = csk} in
    let pk = {pk = cpk} in
    Pi.assume(SK_PK(sk,pk));
    pk, sk

let coerce (pk:pk) (csk:CoreACiphers.sk) =
    let sk= {sk = csk} in
    Pi.assume(SK_PK(sk,pk));
    sk

let repr_of_rsapkey ({ pk = pk }) = pk
let repr_of_rsaskey ({ sk = sk }) = sk

let create_rsapkey ((m, e) : modulus * exponent) = { pk = CoreACiphers.RSAPKey(m, e) }
//let create_rsaskey ((m, e) : modulus * exponent) = { sk = CoreACiphers.RSASKey(m, e) }
