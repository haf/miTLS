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

module SessionDB

open Bytes
open TLSInfo
open Date

(* ------------------------------------------------------------------------------- *)
type StorableSession = SessionInfo * PRF.masterSecret
type SessionIndex = sessionID * Role * Cert.hint
#if ideal
type entry = sessionID * Role * Cert.hint * StorableSession
type t = entry list

let create (c:config) : t = []

let insert (db:t) sid r h sims : t = (sid,r,h,sims)::db

let rec select (db:t) sid r h =
  match db with
  | (sid',r',h',sims)::db when sid=sid' && r=r' && h=h'  -> Some(sims)
  | _::db                                                -> select db sid r h
  | []                                                   -> None

let rec remove (db:t) sid r h =
  match db with
  | (sid',r',h',sims)::db when sid=sid' && r=r' && h=h' -> remove db sid r h
  | e::db                                               -> e::remove db sid r h
  | []                                                  -> []

let rec getAllStoredIDs (db:t) =
  match db with
  | (sid,r,h,sims)::db -> (sid,r,h)::getAllStoredIDs db
  | []                 -> []
#else
open System.IO
open System.Runtime.Serialization.Formatters.Binary

type t = {
    filename: string;
    expiry: TimeSpan;
}

(* ------------------------------------------------------------------------------- *)
module Option =
    let filter (f : 'a -> bool) (x : 'a option) =
        match x with
        | None -> None
        | Some x when f x -> Some x
        | Some x -> None

(* ------------------------------------------------------------------------------- *)
let bytes_of_key (k : SessionIndex) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream () in
        bf.Serialize(m, k); m.ToArray ()

let key_of_bytes (k : byte[]) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream(k) in

        bf.Deserialize(m) :?> SessionIndex

let bytes_of_value (k : StorableSession * DateTime) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream () in
        bf.Serialize(m, k); m.ToArray ()

let value_of_bytes (k : byte[]) =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream(k) in

        bf.Deserialize(m) :?> (StorableSession * DateTime)

(* ------------------------------------------------------------------------------- *)
let create poptions =
    let self = {
        filename = poptions.sessionDBFileName;
          expiry = poptions.sessionDBExpiry;
    }

    DB.closedb (DB.opendb self.filename)
    self

(* ------------------------------------------------------------------------------- *)
let remove self sid role hint =
    let key = bytes_of_key (sid,role,hint) in
    let db  = DB.opendb self.filename in

    try
        DB.tx db (fun db -> ignore (DB.remove db key));
        self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let select self sid role hint =
    let key = bytes_of_key (sid,role,hint) in

    let select (db : DB.db) =
        let filter_record ((sinfo, ts) : StorableSession * _) =
            let expires = addTimeSpan ts self.expiry in

            if greaterDateTime expires (now()) then
                Some sinfo
            else
                ignore (DB.remove db key);
                None
        in

        DB.get db key
            |> Option.map value_of_bytes
            |> Option.bind filter_record

    let db = DB.opendb self.filename in

    try
        DB.tx db select
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let insert self sid role hint value =
    let key = bytes_of_key (sid,role,hint) in
    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key (bytes_of_value (value, now ())) in
    let db = DB.opendb self.filename in
    try
        DB.tx db insert; self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let getAllStoredIDs self =
    let aout =
        let db = DB.opendb self.filename in

        try
            DB.tx db (fun db -> DB.keys db)
        finally
            DB.closedb db
    in
        List.map key_of_bytes aout

#endif
