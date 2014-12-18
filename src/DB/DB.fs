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

module DB

open System
open System.Data
open System.IO

#if __MonoSQL__
open Mono.Data.Sqlite
type SQLiteConnection = SqliteConnection
#else
open System.Data.SQLite
#endif

exception DBError of string

type db = DB of SQLiteConnection

let _db_lock = new Object()

module Internal =
    let wrap (cb : unit -> 'a) =
        try  cb ()
        with exn ->
            fprintfn stderr "DBError: %s" exn.Message;
            raise (DBError (exn.ToString()))

    let opendb (filename : string) =
        ((new FileInfo(filename)).Directory).Create()
        let request = "CREATE TABLE IF NOT EXISTS map(key BLOB PRIMARY KEY, value BLOB NOT NULL)" in
        let urn     = String.Format("Data Source={0};Version=3", filename) in
        let db      = new SQLiteConnection(urn) in
            db.Open();
            db.DefaultTimeout <- 5;
            use command = db.CreateCommand() in
                command.CommandText <- request;
                ignore (command.ExecuteNonQuery() : int);
                DB db

    let closedb (DB db : db) =
        use db = db in ()

    let put (DB db : db) (k : byte[]) (v : byte[]) =
        let request = "INSERT OR REPLACE INTO map (key, value) VALUES (:k, :v)" in
        use command = db.CreateCommand() in
            command.CommandText <- request;
            command.Parameters.Add("k", DbType.Binary).Value <- k;
            command.Parameters.Add("v", DbType.Binary).Value <- v;
            ignore (command.ExecuteNonQuery())

    let get (DB db : db) (k : byte[]) =
        let request = "SELECT value FROM map WHERE key = :k LIMIT 1" in
        use command = db.CreateCommand() in

            command.CommandText <- request;
            command.Parameters.Add("k", DbType.Binary).Value <- k;

            let reader  = command.ExecuteReader() in
                try
                    if reader.Read() then
                        let len  = reader.GetBytes(0, 0L, null, 0, 0) in
                        let data = Array.create ((int) len) 0uy in
                            ignore (reader.GetBytes(0, 0L, data, 0, (int) len) : int64);
                            Some data
                    else
                        None
                finally
                    reader.Close()

    let remove (DB db : db) (k : byte[]) =
        let request = "DELETE FROM map WHERE key = :k" in
        use command = db.CreateCommand() in
            command.CommandText <- request;
            command.Parameters.Add("k", DbType.Binary).Value <- k;
            command.ExecuteNonQuery() <> 0

    let all (DB db : db) =
        let request = "SELECT key, value FROM map" in
        use command = db.CreateCommand() in

            command.CommandText <- request;

            let reader = command.ExecuteReader() in
            let aout   = ref [] in

                try
                    while reader.Read() do
                        let klen  = reader.GetBytes(0, 0L, null, 0, 0) in
                        let vlen  = reader.GetBytes(1, 0L, null, 0, 0) in
                        let kdata = Array.create ((int) klen) 0uy in
                        let vdata = Array.create ((int) vlen) 0uy in
                            ignore (reader.GetBytes(0, 0L, kdata, 0, (int) klen) : int64);
                            ignore (reader.GetBytes(0, 0L, vdata, 0, (int) vlen) : int64);
                            aout := (kdata, vdata) :: !aout
                    done;
                    !aout
                finally
                    reader.Close()

    let keys (DB db : db) =
        let request = "SELECT key FROM map" in
        use command = db.CreateCommand() in

            command.CommandText <- request;

            let reader = command.ExecuteReader() in
            let aout   = ref [] in

                try
                    while reader.Read() do
                        let klen  = reader.GetBytes(0, 0L, null, 0, 0) in
                        let kdata = Array.create ((int) klen) 0uy in
                            ignore (reader.GetBytes(0, 0L, kdata, 0, (int) klen) : int64);
                            aout := kdata :: !aout
                    done;
                    !aout
                finally
                    reader.Close()

    let tx (DB db : db) (f : db -> 'a) : 'a =
        lock (_db_lock) (fun () ->
            use tx = db.BeginTransaction (IsolationLevel.ReadCommitted) in
            let aout = f (DB db) in
                tx.Commit (); aout)

let opendb (filename : string) =
    Internal.wrap (fun () -> Internal.opendb filename)

let closedb (db : db) =
    Internal.wrap (fun () -> Internal.closedb db)

let put (db : db) (k : byte[]) (v : byte[]) =
    Internal.wrap (fun () -> Internal.put db k v)

let get (db : db) (k : byte[]) =
    Internal.wrap (fun () -> Internal.get db k)

let remove (db : db) (k : byte[]) =
    Internal.wrap (fun () -> Internal.remove db k)

let all (db : db) =
    Internal.wrap (fun () -> Internal.all db)

let keys (db : db) =
    Internal.wrap (fun () -> Internal.keys db)

let tx (db : db) (f : db -> 'a) =
    Internal.wrap (fun () -> Internal.tx db f)
