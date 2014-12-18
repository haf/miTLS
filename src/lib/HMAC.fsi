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

module HMAC

open Bytes
open TLSConstants

type key = bytes
type data = bytes
type mac = bytes

val MAC:       macAlg -> key -> data -> mac
val MACVERIFY: macAlg -> key -> data -> mac -> bool

(* SSL/TLS Constants *)

val ssl_pad1_md5: bytes
val ssl_pad2_md5: bytes
val ssl_pad1_sha1: bytes
val ssl_pad2_sha1: bytes
