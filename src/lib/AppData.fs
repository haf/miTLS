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

module AppData

open Error
open Bytes
open TLSInfo
open DataStream
open Range

type input_buffer =  stream * (range * AppFragment.plain) option
type output_buffer =
    | NoneBuf of stream
    | SomeBuf of stream * range * AppFragment.plain * stream

type app_state = {
  app_incoming: input_buffer;
  app_outgoing: output_buffer;
}

let inStream  (c:ConnectionInfo) state =
    let (s,_) = state.app_incoming in s
let outStream (c:ConnectionInfo) state =
    match state.app_outgoing with
    | NoneBuf(s) -> s
    | SomeBuf(s,_,_,_) -> s

let init ci =
  let in_s = DataStream.init ci.id_in in
  let out_s = DataStream.init ci.id_out in
    {app_outgoing = (NoneBuf(out_s));
     app_incoming = (in_s,None)
    }

// Stores appdata in the output buffer, so that it will possibly sent on the network
let writeAppData (c:ConnectionInfo) (a:app_state) (r:range) (f:AppFragment.plain) (s':stream) =
    let s = outStream c a in
    {a with app_outgoing = SomeBuf(s,r,f,s')}

let noneBuf ki s = NoneBuf(s)
let some x = Some x
// When polled, gives Dispatch the next fragment to be delivered,
// and commits to it (adds it to the output stream)
let next_fragment (c:ConnectionInfo) (a:app_state) =
    let out = a.app_outgoing in
    match out with
    | NoneBuf(_) -> None
    | SomeBuf (s,r,f,s') ->
        let b' = noneBuf c.id_out s' in
        some (r,f,{a with app_outgoing = b'})

// Clear contents from the output buffer
let clearOutBuf (c:ConnectionInfo) (a:app_state) =
    let s = outStream c a in
    {a with app_outgoing = NoneBuf(s)}

// Gets a fragment from Dispatch, adds it to the incoming buffer, but not yet to
// the stream of data delivered to the user
let recv_fragment (ci:ConnectionInfo)  (a:app_state)  (r:range) (f:AppFragment.fragment) =
    // pre: snd a.app_incoming = None
    let (s,_) = a.app_incoming in
    let rf = (r,f) in
    {a with app_incoming = (s,Some(rf))}

// Returns the buffered data to the user, and stores them in the stream
let readAppData (c:ConnectionInfo) (a:app_state) =
  let (s,data) = a.app_incoming in
    match data with
      | None -> None,a
      | Some(rf) ->
          let (r,f) = rf in
          let (d,ns) = AppFragment.delta c.id_in s r f in
          let rd = (r,d) in
          Some(rd),{a with app_incoming = (ns,None)}

let reset_outgoing (ci:ConnectionInfo) (a:app_state) (nci:ConnectionInfo) =
  let out_s = DataStream.init nci.id_out in
    {a with
       app_outgoing = NoneBuf(out_s)
    }

let reset_incoming (ci:ConnectionInfo) (a:app_state) (nci:ConnectionInfo) =
  let in_s = DataStream.init nci.id_in in
    {a with
       app_incoming =  (in_s,None)
    }
