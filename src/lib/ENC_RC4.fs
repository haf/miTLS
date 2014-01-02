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

module ENC_RC4

open Bytes
open Encode
open TLSConstants
open TLSInfo
open Error
open TLSError
open Range

type rc4epoch = id
type cipher = bytes
type keyrepr = bytes
type state = { n:nat     (* ghost *)
               u:bool    (* ghost: b ? encryptor : decryptor *)
               k:keyrepr (* ghost, so that we can formally leak it *)
               s:CoreCiphers.rc4engine }
type encryptor = state
type decryptor = state

// Except for this function, we treat CoreCiphers.rc4engine abstractly
// (so we can safely ignore that is it mutated in-place)
let rc4 (e:id) (s:state) (b:bytes) =
  let b' = (CoreCiphers.rc4process s.s (b))
  if length b = length b'
  then
    let s' = {s with n = s.n + 1}
    (s',b')
  else
    unexpected "rc4 is a stream cipher"

#if ideal
type event =
  | ENCrypted of id * LHAEPlain.adata * cipher * plain
type entry = id * LHAEPlain.adata * cipher * plain
let log = ref []
let rec cfind e ad c xs =
  match xs with
  | (e',ad',c',p)::xs' when e=e' && ad=ad' && c=c' -> p
  | (e',ad',c',p)::xs'                             -> cfind e ad c xs'
  | []                                             -> unexpected "the log contains all ENCrypted"
#endif

let encryptor (e:id) (k:keyrepr) = {n=0; k=k; u=true ; s=CoreCiphers.rc4create (k)}
let decryptor (e:id) (k:keyrepr) = {n=0; k=k; u=false; s=CoreCiphers.rc4create (k)}

let GEN (e:id) =
  let k: keyrepr = Nonce.random (encKeySize Stream_RC4_128)
  encryptor e k, decryptor e k

// concrete encryption and decryption

let LEAK    (e:id) s = s.k
let COERCEe (e:id) k = encryptor e k
let COERCEd (e:id) k = decryptor e k

// ideal encryption and decryption (only at safe indexes)
let ENC (e:id) (s:encryptor) (ad:LHAEPlain.adata) (r:range) (p:plain) =
  #if ideal
  if safeId  e then
    let l = targetLength e r
    let s',c = rc4 e s (createBytes l 0)
    Pi.assume (ENCrypted(e,ad,c,p));
    log := (e,ad,c,p)::!log
    (s',c)
  else
  #endif
    let p_mac = repr e ad r p
    let s',c = rc4 e s p_mac
    (s',c)

let DEC (e:id) (s:decryptor) (ad:LHAEPlain.adata) (c:cipher) =
  let s',p = rc4 e s c
  #if ideal
  if safeId  e then
    let p = cfind e ad c !log
    (s',p)
  else
  #endif
  (s', plain e ad (length p) p)
