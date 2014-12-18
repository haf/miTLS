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

module DHGroup

open Bytes
open CoreKeys
open Error
open TLSError

type elt = bytes

#if ideal
type preds = Elt of bytes * bytes * elt
type predPP = PP of bytes * bytes

let goodPP_log = ref([]: list<dhparams>)
#if verify
let goodPP (dhp:dhparams) : bool = failwith "only used in ideal implementation, unverified"
#else
let goodPP dhp =  List.memr !goodPP_log dhp
#endif

let pp (dhp:dhparams) : dhparams =
#if verify
    Pi.assume(PP(dhp.dhp,dhp.dhg));
#else
    goodPP_log := (dhp ::!goodPP_log);
#endif
    dhp
#endif

let genElement dhp: elt =
    let (_, e) = CoreDH.gen_key dhp in
#if verify
    Pi.assume (Elt(dhp.dhp,dhp.dhg,e));
#endif
    e

let checkParams dhdb minSize p g =
    match CoreDH.check_params dhdb minSize p g with
    | Error(x) -> Error(AD_insufficient_security,x)
    | Correct(res) ->
        let (dhdb,dhp) = res in
#if ideal
        let dhp = pp(dhp) in
        let rp = dhp.dhp in
        let rg = dhp.dhg in
        if rp <> p || rg <> g then
            failwith "Trusted code returned inconsitent value"
        else
#endif
        correct (dhdb,dhp)

let checkElement dhp (b:bytes): option<elt> =
    if CoreDH.check_element dhp b then
        (
#if verify
        Pi.assume(Elt(dhp.dhp,dhp.dhg,b));
#endif
        Some(b))
    else
        None

let defaultDHparams file dhdb minSize =
    let (dhdb,dhp) = CoreDH.load_default_params file dhdb minSize in
#if ideal
    let dhp = pp(dhp) in
#endif
    (dhdb,dhp)
