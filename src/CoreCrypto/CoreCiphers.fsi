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

module CoreCiphers

type direction = ForEncryption | ForDecryption

type engine

val blocksize      : engine -> int
val direction      : engine -> direction
val process_blocks : engine -> byte array -> byte array

type key = byte array
type iv  = byte array

type cipher = AES | DES3
type mode   = CBC of iv

val engine : mode option -> direction -> cipher -> byte array -> engine

val encrypt : mode option -> cipher -> key -> byte array (* plain *) -> byte array
val decrypt : mode option -> cipher -> key -> byte array (* plain *) -> byte array

val aes_cbc_encrypt : key -> iv -> byte array -> byte array
val aes_cbc_decrypt : key -> iv -> byte array -> byte array

val des3_cbc_encrypt : key -> iv -> byte array -> byte array
val des3_cbc_decrypt : key -> iv -> byte array -> byte array

type rc4engine

val rc4create  : key -> rc4engine
val rc4process : rc4engine -> byte array -> byte array
