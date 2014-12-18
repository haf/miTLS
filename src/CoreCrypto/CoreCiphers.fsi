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

module CoreCiphers
open Bytes

type key   = bytes
type iv    = bytes
type adata = bytes

val aes_cbc_encrypt : key -> iv -> bytes -> bytes
val aes_cbc_decrypt : key -> iv -> bytes -> bytes

val aes_gcm_encrypt : key -> iv -> adata -> bytes -> bytes
val aes_gcm_decrypt : key -> iv -> adata -> bytes -> bytes option

val des3_cbc_encrypt : key -> iv -> bytes -> bytes
val des3_cbc_decrypt : key -> iv -> bytes -> bytes

type rc4engine

val rc4create  : key -> rc4engine
val rc4process : rc4engine -> bytes -> bytes
