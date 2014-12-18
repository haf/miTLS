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

type sk
type pk = { pk : CoreACiphers.pk }

type modulus  = Bytes.bytes
type exponent = Bytes.bytes

#if ideal
val honest: pk -> bool
val strong: TLSConstants.ProtocolVersion -> bool
#endif

val gen: unit -> pk * sk
val coerce: pk -> CoreACiphers.sk -> sk

val repr_of_rsapkey : pk -> CoreACiphers.pk
val repr_of_rsaskey : sk -> CoreACiphers.sk

val create_rsapkey : modulus * exponent -> pk
//val create_rsaskey : modulus * exponent -> sk
