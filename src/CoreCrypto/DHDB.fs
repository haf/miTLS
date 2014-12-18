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

module DHDB

open System.IO
open System.Runtime.Serialization.Formatters.Binary

open Bytes

type Key   = bytes * bytes
type Value = bytes * bool

type dhdb = {
    filename: string;
}

(* ------------------------------------------------------------------------------- *)
let bytes_of_key (k : Key) : byte[] =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream () in
    let p, g = k in
        bf.Serialize(m, (cbytes p, cbytes g)); m.ToArray ()

let key_of_bytes (k : byte[]) : Key =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream(k) in
    let p, g = bf.Deserialize(m) :?> byte[] * byte[] in
        (abytes p, abytes g)

let bytes_of_value (v : Value) : byte[] =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream () in
    let (q,b) = v in
        bf.Serialize(m, (cbytes q, b)); m.ToArray ()

let value_of_bytes (v : byte[]) : Value =
    let bf = new BinaryFormatter () in
    let m  = new MemoryStream(v) in
    let (q,b) = bf.Deserialize(m) :?> byte[] * bool in
        (abytes q, b)

(* ------------------------------------------------------------------------------- *)
let create (filename:string) =
    let self = {
        filename = filename;
    }
    DB.closedb (DB.opendb self.filename)
    self

(* ------------------------------------------------------------------------------- *)
let remove self key =
    let key = bytes_of_key key in

    let db  = DB.opendb self.filename in

    try
        DB.tx db (fun db -> ignore (DB.remove db key));
        self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let select self key =
    let key = bytes_of_key key in

    let select (db : DB.db) =
        DB.get db key
            |> Option.map value_of_bytes

    let db = DB.opendb self.filename in

    try
        DB.tx db select
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let insert self key v =
    let key = bytes_of_key key in

    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key (bytes_of_value v) in

    let db = DB.opendb self.filename in

    try
        DB.tx db insert; self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let keys self =
    let aout =
        let db = DB.opendb self.filename in

        try
            DB.tx db (fun db -> DB.keys db)
        finally
            DB.closedb db
    in
        List.map key_of_bytes aout
