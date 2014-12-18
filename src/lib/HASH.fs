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

module HASH

open Bytes
open TLSConstants

(* Parametric hash algorithm (implements interface) *)
let hash' alg data =
    match alg with
    | NULL    -> data
    | MD5SHA1 -> (CoreHash.md5 data) @| (CoreHash.sha1 data)
    | MD5     -> (CoreHash.md5    data)
    | SHA     -> (CoreHash.sha1   data)
    | SHA256  -> (CoreHash.sha256 data)
    | SHA384  -> (CoreHash.sha384 data)

let hash alg data =
  let h = hash' alg data in
  let l = length h in
  let exp = hashSize alg in
  if l = exp then h
  else Error.unexpected "CoreHash returned a hash of an unexpected size"
