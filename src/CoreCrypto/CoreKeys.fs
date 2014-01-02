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

module CoreKeys
open Bytes
type modulus  = bytes
type exponent = bytes

type rsapkey = modulus * exponent
type rsaskey = modulus * exponent

type dsaparams = { p : bytes; q : bytes; g : bytes; }

type dsapkey = bytes * dsaparams
type dsaskey = bytes * dsaparams

type dhparams = { p : bytes; g : bytes }

type dhpbytes = bytes
type dhsbytes = bytes

type dhpkey = dhpbytes * dhparams
type dhskey = dhsbytes * dhparams
