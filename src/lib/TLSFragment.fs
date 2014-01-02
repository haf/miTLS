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

module TLSFragment

open Error
open TLSError
open Bytes
open TLSInfo
open TLSConstants
open Range

type fragment =
    | FHandshake of HSFragment.fragment //Cf Handshake.fragment
    | FCCS of HSFragment.fragment
    | FAlert of HSFragment.fragment
    | FAppData of AppFragment.fragment
type plain = fragment

type history = {
  handshake: HSFragment.stream
  ccs:       HSFragment.stream
  alert:     HSFragment.stream
  appdata:   DataStream.stream
}

let emptyHistory e =
    let i = id e in
    let es = HSFragment.init i in
    let ehApp = DataStream.init e in
    { handshake = es;
      ccs = es;
      alert = es;
      appdata = ehApp}

let handshakeHistory (e:epoch) h = h.handshake
let ccsHistory (e:epoch) h = h.ccs
let alertHistory (e:epoch) h = h.alert

let fragment i ct rg b =
    match ct with
    | Handshake          -> FHandshake(HSFragment.fragmentPlain i rg b)
    | Change_cipher_spec -> FCCS(HSFragment.fragmentPlain i rg b)
    | Alert              -> FAlert(HSFragment.fragmentPlain i rg b)
    | Application_data   -> FAppData(AppFragment.plain i rg b)

let plain e (ct:ContentType) (h:history) (rg:range) b =
      let i = id e in
        fragment i ct rg b

let reprFragment i (ct:ContentType) (rg:range) frag =
    match frag with
    | FHandshake(f) -> HSFragment.fragmentRepr i rg f
    | FCCS(f)       -> HSFragment.fragmentRepr i rg f
    | FAlert(f)     -> HSFragment.fragmentRepr i rg f
    | FAppData(f)   -> AppFragment.repr i rg f

let repr e ct (h:history) rg frag =
  let i = id e in
  reprFragment i ct rg frag

let HSPlainToRecordPlain    (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FHandshake(f)
let CCSPlainToRecordPlain   (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FCCS(f)
let AlertPlainToRecordPlain (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FAlert(f)
let AppPlainToRecordPlain   (e:epoch) (h:history) (r:range) (f:AppFragment.plain)= FAppData(f)

let RecordPlainToHSPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FHandshake(f) -> f
    | FCCS(_)
    | FAlert(_)
    | FAppData(_)   -> unreachable "[RecordPlainToHSPlain] invoked on an invalid fragment"
let RecordPlainToCCSPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FCCS(f)       -> f
    | FHandshake(_)
    | FAlert(_)
    | FAppData(_)   -> unreachable "[RecordPlainToCCSPlain] invoked on an invalid fragment"
let RecordPlainToAlertPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FAlert(f)     -> f
    | FHandshake(_)
    | FCCS(_)
    | FAppData(_)   -> unreachable "[RecordPlainToAlertPlain] invoked on an invalid fragment"
let RecordPlainToAppPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FAppData(f)   -> f
    | FHandshake(_)
    | FCCS(_)
    | FAlert(_)     -> unreachable "[RecordPlainToAppPlain] invoked on an invalid fragment"

let extendHistory (e:epoch) ct ss r frag =
  let i = id e in
  match ct,frag with
    | Handshake,FHandshake(f)      -> let s' = HSFragment.extend i ss.handshake r f in
                                      {ss with handshake = s'}
    | Alert,FAlert(f)              -> let s' = HSFragment.extend i ss.alert r f in
                                      {ss with alert = s'}
    | Change_cipher_spec,FCCS(f)   -> let s' = HSFragment.extend i ss.ccs r f in
                                      {ss  with ccs = s'}
    | Application_data,FAppData(f) -> let d,s' = AppFragment.delta e ss.appdata r f in
                                      {ss with appdata = s'}
    | _,_                          -> unexpected "[extendHistory] invoked on an invalid contenttype/fragment"

#if ideal
let widen i ct r0 f0 =
    let r1 = rangeClass i r0 in
    match ct,f0 with
    | Handshake,FHandshake(f)      -> let f1 = HSFragment.widen i r0 r1 f in
                                      FHandshake(f1)
    | Alert,FAlert(f)              -> let f1 = HSFragment.widen i r0 r1 f in
                                      FAlert(f1)
    | Change_cipher_spec,FCCS(f)   -> let f1 = HSFragment.widen i r0 r1 f in
                                      FCCS(f1)
    | Application_data,FAppData(f) -> let f1 = AppFragment.widen i r0 f in
                                      FAppData(f1)
    | _,_                          -> unexpected "[widen] invoked on an invalid contenttype/fragment"

#endif
