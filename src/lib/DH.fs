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

module DH

open Bytes
open DHGroup
open CoreKeys

type secret = Key of bytes

#if ideal
// Local predicate definitions
type predHE = HonestExponential of bytes * bytes * elt
#endif

#if ideal
// log of honestly generated elements
type honest_entry = (dhparams * elt)
let honest_log = ref([]: list<honest_entry>)
#if verify
let honest dhp gx = failwith "only used in ideal implementation, unverified"
#else
let honest dhp gx = List.exists (fun el-> el = (dhp,gx)) !honest_log
#endif

let safeDH (dhp:dhparams) (gx:elt) (gy:elt): bool =
    honest dhp gx && honest dhp gy && goodPP dhp
#endif

#if ideal
// log for looking up good pms values using their id
type entry = dhparams * elt * elt * PMS.dhpms
let log: list<entry> ref = ref []
let rec assoc (dhp:dhparams) (gx:elt) (gy:elt) entries: option<PMS.dhpms> =
    match entries with
    | []                      -> None
    | (dhp',gx',gy', pms)::entries when dhp=dhp' && gx=gx' && gy=gy' -> Some(pms)
    | _::entries              -> assoc dhp gx gy entries
#endif

let leak   (dhp:dhparams) (gx:elt) (Key(b)) = b
let coerce (dhp:dhparams) (gx:elt) b = Key(b)

let genKey dhp: elt * secret =
    let (x,e) = CoreDH.gen_key dhp in
    #if ideal
    #if verify
    Pi.assume(Elt(dhp.dhp,dhp.dhg,e));
    Pi.assume(HonestExponential(dhp.dhp,dhp.dhg,e));
    #else
    honest_log := (dhp,e)::!honest_log;
    #endif
    #endif
    (e, Key (x))

let serverGen filename dhdb minSize =
    let (dhdb,dhp) = defaultDHparams filename dhdb minSize in
    let (e,s) = genKey dhp in
    (dhdb,dhp,e,s)

let clientGenExp dhp gs =
    let (gc,c) = genKey dhp in
    let (Key ck) = c in
    let p = dhp.dhp in
    let pms = CoreDH.agreement p ck gs in
    //#begin-ideal
    #if ideal
    if safeDH dhp gs gc then
      match assoc dhp gs gc !log with
      | Some(pms) -> (gc,pms)
      | None ->
                 let pms=PMS.sampleDH dhp gs gc in
                 log := (dhp,gs,gc,pms)::!log;
                 (gc,pms)
    else
      (Pi.assume(DHGroup.Elt(dhp.dhp,dhp.dhg,pms));
      let dpms = PMS.coerceDH dhp gs gc pms in
      (gc,dpms))
    //#end-ideal
    #else
    let dpms = PMS.coerceDH dhp gs gc pms in
    (gc,dpms)
    #endif

let serverExp dhp gs gc sk =
    let (Key s) = sk in
    let p = dhp.dhp in
    let pms = CoreDH.agreement p s gc in
    //#begin-ideal
    #if ideal
    if safeDH dhp gs gc then
      match assoc dhp gs gc !log with
      | Some(pms) -> pms
      | None ->
                 let pms=PMS.sampleDH dhp gs gc in
                 log := (dhp,gs,gc,pms)::!log;
                 pms
    else
      (Pi.assume(DHGroup.Elt(dhp.dhp,dhp.dhg,pms));
      let dpms = PMS.coerceDH dhp gs gc pms in
      dpms)
    //#end-ideal
    #else
    let dpms = PMS.coerceDH dhp gs gc pms in
    dpms
    #endif
