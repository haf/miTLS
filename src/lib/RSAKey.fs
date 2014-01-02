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

module RSAKey

open Bytes

type pk = { pk : CoreACiphers.pk }
type sk = { sk : CoreACiphers.sk }

#if ideal

let honest_log = ref[]
let honest (pk:pk) = false
#endif

type modulus  = bytes
type exponent = bytes

let create_rsaskey ((m, e) : modulus * exponent) = { sk = CoreACiphers.RSASKey(m, e) }
let create_rsapkey ((m, e) : modulus * exponent) = { pk = CoreACiphers.RSAPKey(m, e) }

let repr_of_rsapkey ({ pk = pk }) = pk
let repr_of_rsaskey ({ sk = sk }) = sk
