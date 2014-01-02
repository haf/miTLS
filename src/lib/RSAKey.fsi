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

type sk
type pk

type modulus  = Bytes.bytes
type exponent = Bytes.bytes

#if ideal
val honest: pk -> bool
#endif

val create_rsapkey : modulus * exponent -> pk
val create_rsaskey : modulus * exponent -> sk

val repr_of_rsapkey : pk -> CoreACiphers.pk
val repr_of_rsaskey : sk -> CoreACiphers.sk
