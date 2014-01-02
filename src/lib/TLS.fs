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

module TLS

open Bytes
open Error
open TLSError
open TLSInfo
open Tcp
open Dispatch

type Connection = Dispatch.Connection
type nextCn = Connection

// Outcomes for top-level functions
type ioresult_i =
    | ReadError of alertDescription option * string
    | Close     of Tcp.NetworkStream
    | Fatal     of alertDescription
    | Warning   of nextCn * alertDescription
    | CertQuery of nextCn * query * bool
    | Handshaken of Connection
    | Read      of nextCn * msg_i
    | DontWrite of Connection

type ioresult_o =
    | WriteError    of alertDescription option * string
    | WriteComplete of nextCn
    | WritePartial  of nextCn * msg_o
    | MustRead      of Connection

let connect ns po = Dispatch.init ns Client po
let resume ns sid po = Dispatch.resume ns sid po

let rehandshake c po = Dispatch.rehandshake c po
let rekey c po = Dispatch.rekey c po

let accept list po =
    let ns = Tcp.accept list in
    Dispatch.init ns Server po
let accept_connected ns po = Dispatch.init ns Server po

let request c po = Dispatch.request c po

let read ca =
  let cb,outcome = Dispatch.read ca in
    match outcome with
      | WriteOutcome(WError(err)) -> ReadError(None,err)
      | RError(err) -> ReadError(None,err)
      | RAppDataDone(b) -> Read(cb,b)
      | RQuery(q,adv) -> CertQuery(cb,q,adv)
      | RHSDone -> Handshaken(cb)
      | RClose -> Close (networkStream cb)
      | RFatal(ad) -> Fatal(ad)
      | RWarning(ad) -> Warning(cb,ad)
      | WriteOutcome(WMustRead) -> DontWrite(cb)
      | WriteOutcome(WHSDone) -> Handshaken (cb)
      | WriteOutcome(SentFatal(ad,s)) -> ReadError(Some(ad),s)
      | WriteOutcome(SentClose) -> Close (networkStream cb)
      | WriteOutcome(WriteAgain) -> unexpected "[read] Dispatch.read should never return WriteAgain"
      | _ -> ReadError(None, perror __SOURCE_FILE__ __LINE__ "Invalid dispatcher state. This is probably a bug, please report it")

let write c msg =
    let c,outcome,rdOpt = Dispatch.write c msg in
    match outcome with
      | WError(err) -> WriteError(None,err)
      | WAppDataDone ->
            match rdOpt with
              | None -> WriteComplete c
              | Some(rd) -> WritePartial (c,rd)
      | WHSDone ->
          (* A top-level write should never lead to HS completion.
             Currently, we report this as an internal error.
             Being more precise about the Dispatch state machine, we should be
             able to prove that this case should never happen, and so use the
             unexpected function. *)
          WriteError(None, perror __SOURCE_FILE__ __LINE__ "Invalid dispatcher state. This is probably a bug, please report it")
      | WMustRead ->
          MustRead(c)
      | SentClose ->
          (* A top-level write can never send a closure alert on its own.
             Either the user asks for half_shutdown, and the connection is consumed,
             or it asks for full_shutdown, and then it cannot write anymore *)
          WriteError(None, perror __SOURCE_FILE__ __LINE__ "Invalid dispatcher state. This is probably a bug, please report it")
      | SentFatal(ad,err) ->
          WriteError(Some(ad),err)
      | WriteAgain | WriteAgainFinishing ->
          unexpected "[write] writeAll should never ask to write again"

let full_shutdown c = Dispatch.full_shutdown c
let half_shutdown c = Dispatch.half_shutdown c

let authorize c q =
    let cb,outcome = Dispatch.authorize c q in
    match outcome with
      | WriteOutcome(WError(err)) -> ReadError(None,err)
      | RError(err) -> ReadError(None,err)
      | RHSDone -> Handshaken(cb)
      | RClose -> Close (networkStream cb)
      | RFatal(ad) -> Fatal(ad)
      | RWarning(ad) -> Warning(cb,ad)
      | WriteOutcome(WMustRead) -> DontWrite(cb)
      | WriteOutcome(WHSDone) -> Handshaken (cb)
      | WriteOutcome(SentFatal(ad,s)) -> ReadError(Some(ad),s)
      | WriteOutcome(SentClose) -> Close (networkStream cb)
      | WriteOutcome(WriteAgain) -> unexpected "[read] Dispatch.read should never return WriteAgain"
      | _ -> ReadError(None, perror __SOURCE_FILE__ __LINE__ "Invalid dispatcher state. This is probably a bug, please report it")

let refuse c q = Dispatch.refuse c q

let getEpochIn c = Dispatch.getEpochIn c
let getEpochOut c = Dispatch.getEpochOut c
let getSessionInfo ki = epochSI(ki)
let getInStream  c = Dispatch.getInStream c
let getOutStream c = Dispatch.getOutStream c
