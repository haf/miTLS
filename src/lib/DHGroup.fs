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

module DHGroup

open Bytes
open CoreKeys

type p   = bytes
type elt = bytes
type g   = bytes
type q   = bytes

type preds = Elt of p * g * elt

let dhparams p g q: CoreKeys.dhparams = { p = p; g = g; q = q }

let genElement p g q: elt =
    let (_, (e, _)) = CoreDH.gen_key (dhparams p g q) in
#if verify
    Pi.assume (Elt(p,g,e));
#endif
    e

let checkElement (p:p) (g:g) (b:bytes): option<elt> =
    if CoreDH.check_element p g b then
#if verify
        Pi.assume(Elt(p,g,b));
#endif
        Some(b)
    else
        None
