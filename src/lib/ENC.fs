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

module ENC

open Bytes
open Error
open TLSConstants
open TLSInfo
open Range

(* We do not open Encode so that we can syntactically check its usage restrictions *)

type cipher = bytes

(* Early TLS chains IVs but this is not secure against adaptive CPA *)
let lastblock cipher alg =
    let ivl = blockSize alg in
    let (_,b) = split cipher (length cipher - ivl) in b

type key = {k:bytes}

type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV

type blockState =
    {key: key;
     iv: iv3}
type streamState =
    {skey: key; // Ghost: Only stored so that we can LEAK it
     sstate: CoreCiphers.rc4engine}

type state =
    | BlockCipher of blockState
    | StreamCipher of streamState
type encryptor = state
type decryptor = state

let GENOne ki =
    let si = epochSI(ki) in
    let alg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match alg with
    | Stream_RC4_128 ->
        let k = Nonce.mkRandom (encKeySize alg) in
        let key = {k = k} in
        StreamCipher({skey = key; sstate = CoreCiphers.rc4create k})
    | CBC_Stale(cbc) ->
        let key = {k = Nonce.mkRandom (encKeySize alg)}
        let iv = SomeIV(Nonce.mkRandom (blockSize cbc))
        BlockCipher ({key = key; iv = iv})
    | CBC_Fresh(_) ->
        let key = {k = Nonce.mkRandom (encKeySize alg)}
        let iv = NoIV
        BlockCipher ({key = key; iv = iv})

let GEN (ki) = let k = GENOne ki in (k,k)

let COERCE (ki:epoch) k iv =
    let si = epochSI(ki) in
    let alg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match alg with
    | Stream_RC4_128 ->
        let key = {k = k} in
        StreamCipher({skey = key; sstate = CoreCiphers.rc4create k})
    | CBC_Stale(_) ->
        BlockCipher ({key = {k=k}; iv = SomeIV(iv)})
    | CBC_Fresh(_) ->
        BlockCipher ({key = {k=k}; iv = NoIV})

let LEAK (ki:epoch) s =
    match s with
    | BlockCipher (bs) ->
        let iv =
            match bs.iv with
            | NoIV -> [||]
            | SomeIV(iv) -> iv
        (bs.key.k,iv)
    | StreamCipher (ss) ->
        ss.skey.k,[||]

let cbcenc alg k iv d =
    match alg with
    | TDES_EDE -> CoreCiphers.des3_cbc_encrypt k iv d
    | AES_128 | AES_256  -> CoreCiphers.aes_cbc_encrypt  k iv d

(* Parametric ENC/DEC functions *)
let ENC_int ki s tlen d =
    let si = epochSI(ki) in
    let encAlg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match s,encAlg with
    //#begin-ivStaleEnc
    | BlockCipher(s), CBC_Stale(alg) ->
        match s.iv with
        | NoIV -> unexpectedError "[ENC] Wrong combination of cipher algorithm and state"
        | SomeIV(iv) ->
            let cipher = cbcenc alg s.key.k iv d
            if length cipher <> tlen || tlen > max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
            else
                let s = {s with iv = SomeIV(lastblock cipher alg) } in
                (BlockCipher(s), cipher)
    //#end-ivStaleEnc
    | BlockCipher(s), CBC_Fresh(alg) ->
        match s.iv with
        | SomeIV(b) -> unexpectedError "[ENC] Wrong combination of cipher algorithm and state"
        | NoIV   ->
            let ivl = blockSize alg in
            let iv = Nonce.mkRandom ivl in
            let cipher = cbcenc alg s.key.k iv d
            let res = iv @| cipher in
            if length res <> tlen || tlen > max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
            else
                let s = {s with iv = NoIV} in
                (BlockCipher(s), res)
    | StreamCipher(s), Stream_RC4_128 ->
        let cipher = CoreCiphers.rc4process s.sstate d in
        if length cipher <> tlen || tlen > max_TLSCipher_fragment_length then
                // unexpected, because it is enforced statically by the
                // CompatibleLength predicate
                unexpectedError "[ENC] Length of encrypted data do not match expected length"
        else
            (StreamCipher(s),cipher)
    | _, _ -> unexpectedError "[ENC] Wrong combination of cipher algorithm and state"

#if ideal
type entry = epoch * LHAEPlain.adata * cipher * Encode.plain
let log:entry list ref = ref []
let rec cfind (e:epoch) (c:cipher) (xs: entry list) =
  match xs with
      [] -> failwith "not found"
    | (e',ad,c',text)::res when e = e' && c = c' -> (ad,cipherRangeClass e (length c),text)
    | _::res -> cfind e c res
#endif

let ENC ki s ad rg data =
    let tlen = targetLength ki rg in
  #if ideal
    if safeENC(ki) then
      let d = createBytes tlen 0 in
      let (s,c) = ENC_int ki s tlen d in
      log := (ki, ad, c, data)::!log;
      (s,c)
    else
  #endif
      let d = Encode.repr ki ad rg data in
      ENC_int ki s tlen d

let cbcdec alg k iv e =
    match alg with
    | TDES_EDE -> CoreCiphers.des3_cbc_decrypt k iv e
    | AES_128 | AES_256  -> CoreCiphers.aes_cbc_decrypt k iv e

let DEC_int ki s cipher =
    let si = epochSI(ki) in
    let encAlg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    match s, encAlg with
    //#begin-ivStaleDec
    | BlockCipher(s), CBC_Stale(alg) ->
        match s.iv with
        | NoIV -> unexpectedError "[DEC] Wrong combination of cipher algorithm and state"
        | SomeIV(iv) ->
            let data = cbcdec alg s.key.k iv cipher
            let s = {s with iv = SomeIV(lastblock cipher alg)} in
            (BlockCipher(s), data)
    //#end-ivStaleDec
    | BlockCipher(s), CBC_Fresh(alg) ->
        match s.iv with
        | SomeIV(_) -> unexpectedError "[DEC] Wrong combination of cipher algorithm and state"
        | NoIV ->
            let ivL = blockSize alg in
            let (iv,encrypted) = split cipher ivL in
            let data = cbcdec alg s.key.k iv encrypted in
            let s = {s with iv = NoIV} in
            (BlockCipher(s), data)
    | StreamCipher(s), Stream_RC4_128 ->
        let data = CoreCiphers.rc4process s.sstate cipher
        (StreamCipher(s),data)
    | _,_ -> unexpectedError "[DEC] Wrong combination of cipher algorithm and state"

let DEC ki s ad cipher =
  #if ideal
    if safeENC(ki) then
      let (s,p) = DEC_int ki s cipher in
      let (ad',rg',p') = cfind ki cipher !log in
      (s,p')
    else
  #endif
      let (s,p) = DEC_int ki s cipher in
      let tlen = length cipher in
      let p' = Encode.plain ki ad tlen p in
      (s,p')

(* the SPRP game in F#, without indexing so far.
   the adversary gets
   enc: block -> block
   dec: block -> block

// two copies of assoc
let rec findp pcs c =
  match pcs with
  | (p,c')::pcs -> if c = c' then Some(p) else findp pcs c
  | [] -> None
let rec findc pcs p =
  match pcs with
  | (p',c)::pcs -> if p = p' then Some(c) else findc pcs p
  | [] -> None

let k = mkRandom blocksize
let qe = ref 0
let qd = ref 0
#if ideal
let log = ref ([] : (block * block) list)
let F p =
  match findc !pcs p with
  | Some(c) -> c // non-parametric;
                 // after CBC-collision avoidance,
                 // we will always use the "None" case
  | None    -> let c = mkfreshc !log blocksize
               log := (p,c)::!log
               c
let G c =
  match findp !log c with
  | Some(p) -> p
  | None    -> let p = mkfreshp !log blocksize
               log := (p,c)::!log
               p
#else
let F = AES k
let G = AESminus k
#endif
let enc p = incr qe; F p
let dec c = incr qd; G c
*)
