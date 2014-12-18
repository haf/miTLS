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

module DH

open Bytes
open DHGroup
open CoreKeys

type secret = Key of bytes

#if ideal
type honest_entry = (p * g * elt)
type good_entry = (p * g)
let goodPP_log = ref([]: list<good_entry>)
let honest_log = ref([]: list<honest_entry>)
let log = ref []
#if verify
let goodPP p g = failwith "only used in ideal implementation, unverified"
let honest p g gx = failwith "only used in ideal implementation, unverified"
#else
let goodPP p g =  List.exists (fun el-> el = (p,g)) !goodPP_log
let honest p g gx = List.exists (fun el-> el = (p,g,gx)) !honest_log
#endif
#endif

type predPP = PP of p * g

let pp (pg:dhparams) : p * g * (option<q>) =
    let p=pg.p
    //let pgg = pg.g
    //let goption = DHGroup.checkElement p pgg pgg
    //let g = match goption with
    //        | None -> Error.unexpected("Invalid DH generator") //failwith "Invalid DH generator"
    //        | Some b -> b
    let g = pg.g
    #if ideal
    #if verify
    Pi.assume(Elt(p,g,g));
    Pi.assume(DHGroup.PP(p,g));
    #else
    goodPP_log := ((p,g) ::!goodPP_log)
    #endif
    #endif
    (p,g,pg.q)

let gen_pp()     = pp (CoreDH.gen_params())

let default_pp() = pp (CoreDH.load_default_params())

type predHE = HonestExponential of p * g * elt

let genKey p g q: elt * secret =
    let ((x, _), (ce, _)) = CoreDH.gen_key (DHGroup.dhparams p g q)
    //let eoption = DHGroup.checkElement p g ce
    //let e = match eoption with
    //        | None -> Error.unexpected("Invalid DH generator") //failwith "Invalid DH generator"
    //        | Some b -> b
    let e=ce
    #if ideal
    #if verify
    Pi.assume(Elt(p,g,e));
    Pi.assume(HonestExponential(p,g,e));
    #else
    honest_log := (p,g,e)::!honest_log
    #endif
    #endif
    (e, Key (x))

#if ideal
// We maintain a log for looking up good ms values using their msId
type entry = p* g * elt * elt * PMS.dhpms
let rec assoc (p:p) (g:g) (gx:elt) (gy:elt) entries: option<PMS.dhpms> =
    match entries with
    | []                      -> None
    | (p',g',gx',gy', pms)::entries when p = p' && g=g' && gx=gx' && gy=gy' -> Some(pms)
    | _::entries              -> assoc p g gx gy entries

let safeDH (p:p) (g:g) (gx:elt) (gy:elt): bool =
    honest p g gx && honest p g gy && goodPP p g
    #endif

let serverGen () =
    let (p,g,q) = default_pp() in
    let (e,s) = genKey p g q in
    (p,g,e,s)

let clientGenExp p g gs =
    let (gc, c) = genKey p g None in
    let (Key ck) = c in
    let pms = (CoreDH.agreement (dhparams p g None) (ck) (gs)) in
    //#begin-ideal
    #if ideal
    if honest p g gs && honest p g gc && goodPP p g
    then
      match assoc p g gs gc !log with
      | Some(pms) -> (gc,c,pms)
      | None ->
                 let pms=PMS.sampleDH p g gs gc
                 log := (p,g,gs,gc,pms)::!log;
                 (gc,c,pms)
    else
      Pi.assume(DHGroup.Elt(p,g,pms)); //use checkElement instead
      let dpms = PMS.coerceDH p g gs gc pms in
      (gc,c, dpms)
    //#end-ideal
    #else
    let dpms = PMS.coerceDH p g gs gc pms in
    (gc,c, dpms)
    #endif

let serverExp p g gs gc sk =
    let (Key s) = sk in
    let pms = (CoreDH.agreement (dhparams p g None) (s) (gc)) in
    //#begin-ideal
    #if ideal
    if honest p g gs && honest p g gc && goodPP p g
    then
      match assoc p g gs gc !log with
      | Some(pms) -> pms
      | None ->
                 let pms=PMS.sampleDH p g gs gc in
                 log := (p,g,gs,gc,pms)::!log;
                 pms
    else
      Pi.assume(DHGroup.Elt(p,g,pms)); //use checkElement instead
      let dpms = PMS.coerceDH p g gs gc pms in
      dpms
    //#end-ideal
    #else
    let dpms = PMS.coerceDH p g gs gc pms in
    dpms
    #endif
