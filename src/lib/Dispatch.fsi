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

module Dispatch

open Bytes
open TLSConstants
open Tcp
open Error
open Record
open Handshake
open TLSInfo
open DataStream
open Range

[<NoEquality;NoComparison>]
type Connection
type nextCn = Connection
type nullCn = Connection
type query = Cert.chain
type msg_i = (range * delta)
type msg_o = (range * delta)

val networkStream: Connection -> NetworkStream

val init: NetworkStream -> Role -> config -> Connection

val resume: NetworkStream -> sessionID -> config -> Connection

val rehandshake: Connection -> config -> bool * nextCn
val rekey: Connection -> config -> bool * nextCn
val request: Connection -> config -> bool * nextCn

val full_shutdown: Connection -> Connection
val half_shutdown: Connection -> unit

type writeOutcome =
    | WError of string (* internal *)
    | WriteAgain (* Possibly more data to send *)
    | WriteAgainFinishing (* Possibly more data to send, and the outgoing epoch changed *)
    | WAppDataDone (* No more data to send in the current state *)
    | WHSDone
    | WMustRead (* Read until completion of Handshake *)
    | SentFatal of alertDescription * string (* The alert that has been sent *)
    | SentClose

type readOutcome =
    | WriteOutcome of writeOutcome
    | RError of string (* internal *)
    | RAgain
    | RAppDataDone
    | RQuery of query * bool
    | RHSDone
    | RClose
    | RFatal of alertDescription (* The received alert *)
    | RWarning of alertDescription (* The received alert *)

val write: Connection -> msg_o -> Connection * writeOutcome * msg_o option
val read: Connection -> Connection * readOutcome * msg_i option

val authorize: Connection -> query -> Connection * readOutcome * msg_i option
val refuse:    Connection -> query -> unit

val getEpochIn:  Connection -> epoch
val getEpochOut: Connection -> epoch
val getInStream:  Connection -> stream
val getOutStream: Connection -> stream
