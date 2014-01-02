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

type modulus  = byte array
type exponent = byte array

type rsapkey = modulus * exponent
type rsaskey = modulus * exponent

type dsaparams = { p : byte array; q : byte array; g : byte array; }

type dsapkey = byte array * dsaparams
type dsaskey = byte array * dsaparams

type dhparams = { p : byte array; g : byte array }

type dhpbytes = byte array
type dhsbytes = byte array

type dhpkey = dhpbytes * dhparams
type dhskey = dhsbytes * dhparams
