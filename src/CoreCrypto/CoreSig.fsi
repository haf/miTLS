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

module CoreSig

(* ------------------------------------------------------------------------ *)
type sighash =
| SH_MD5
| SH_SHA1
| SH_SHA256
| SH_SHA384

type sigalg =
| SA_RSA
| SA_DSA

(* ------------------------------------------------------------------------ *)
type sigskey =
| SK_RSA of CoreKeys.rsaskey
| SK_DSA of CoreKeys.dsaskey

type sigpkey =
| PK_RSA of CoreKeys.rsapkey
| PK_DSA of CoreKeys.dsapkey

val sigalg_of_skey : sigskey -> sigalg
val sigalg_of_pkey : sigpkey -> sigalg

(* ------------------------------------------------------------------------ *)
type text = byte array
type sigv = byte array

val gen    : sigalg -> sigpkey * sigskey
val sign   : sighash option -> sigskey -> text -> sigv
val verify : sighash option -> sigpkey -> text -> sigv -> bool
