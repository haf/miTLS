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

module TLStream

open Bytes
open Tcp
open Error
open System
open System.IO

type TLSBehavior =
    | TLSClient
    | TLSServer

type TLStream(s:System.IO.Stream, options, b, ?own) =
    inherit Stream()

    let own = defaultArg own true

    let mutable inbuf  : bytes = [||]
    let mutable outbuf : bytes = [||]
    let mutable closed : bool  = true

    let doMsg_o conn b =
        let ki = TLS.getEpochOut conn
        let s = TLS.getOutStream conn
        let l = length b
        (l,l),DataStream.createDelta ki s (l,l) b

    let undoMsg_i conn (r,d) =
        let ki = TLS.getEpochIn conn
        let s = TLS.getInStream conn
        DataStream.deltaRepr ki s r d

    let rec doHS conn =
        match TLS.read conn with
        | TLS.ReadError (adOpt,err) ->
            match adOpt with
            | Some(ad) -> raise (IOException(sprintf "TLS-HS: Sent fatal alert: %A %A" ad err))
            | None     -> raise (IOException(sprintf "TLS-HS: Internal error: %A" err))
        | TLS.Close ns -> raise (IOException(sprintf "TLS-HS: Connection closed during HS"))
        | TLS.Fatal ad -> raise (IOException(sprintf "TLS-HS: Received fatal alert: %A" ad))
        | TLS.Warning (conn,ad) -> raise (IOException(sprintf "TLS-HS: Received warning alert: %A" ad))
        | TLS.CertQuery (conn,q,advice) ->
            if advice then
                match TLS.authorize conn q with
                | TLS.ReadError (adOpt,err) ->
                    match adOpt with
                    | Some(ad) -> raise (IOException(sprintf "TLS-HS: Sent fatal alert: %A %A" ad err))
                    | None     -> raise (IOException(sprintf "TLS-HS: Internal error: %A" err))
                | TLS.Close ns -> raise (IOException(sprintf "TLS-HS: Connection closed during HS"))
                | TLS.Fatal ad -> raise (IOException(sprintf "TLS-HS: Received fatal alert: %A" ad))
                | TLS.Warning (conn,ad) -> raise (IOException(sprintf "TLS-HS: Received warning alert: %A" ad))
                | TLS.CertQuery (conn,q,advice) -> raise (IOException(sprintf "TLS-HS: Asked to authorize a certificate twice"))
                | TLS.Handshaken conn -> closed <- false; conn
                | TLS.Read (conn,msg) ->
                    let b = undoMsg_i conn msg
                    inbuf <- inbuf @| b
                    doHS conn
                | TLS.DontWrite conn -> doHS conn
            else
                TLS.refuse conn q
                raise (IOException(sprintf "TLS-HS: Refusing untrusted certificate"))
        | TLS.Handshaken conn -> closed <- false; conn
        | TLS.Read (conn,msg) ->
            let b = undoMsg_i conn msg
            inbuf <- inbuf @| b
            doHS conn
        | TLS.DontWrite conn -> doHS conn

    let rec wrapRead conn =
        match TLS.read conn with
        | TLS.ReadError (adOpt,err) ->
            match adOpt with
            | None -> raise (IOException(sprintf "TLS-HS: Internal error: %A" err))
            | Some ad -> raise (IOException(sprintf "TLS-HS: Sent fatal alert: %A %A" ad err))
        | TLS.Close ns -> closed <- true; (conn,[||]) // This is a closed connection, should not be used!
        | TLS.Fatal ad -> raise (IOException(sprintf "TLS-HS: Received fatal alert: %A" ad))
        | TLS.Warning (conn,ad) -> raise (IOException(sprintf "TLS-HS: Received warning alert: %A" ad))
        | TLS.CertQuery (conn,q,advice) ->
            if advice then
                match TLS.authorize conn q with
                | TLS.ReadError (adOpt,err) ->
                    match adOpt with
                    | None -> raise (IOException(sprintf "TLS-HS: Internal error: %A" err))
                    | Some ad -> raise (IOException(sprintf "TLS-HS: Sent fatal alert: %A %A" ad err))
                | TLS.Close ns -> closed <- true; (conn,[||]) // This is a closed connection, should not be used!
                | TLS.Fatal ad -> raise (IOException(sprintf "TLS-HS: Received fatal alert: %A" ad))
                | TLS.Warning (conn,ad) -> raise (IOException(sprintf "TLS-HS: Received warning alert: %A" ad))
                | TLS.CertQuery (conn,q,advice) -> raise (IOException(sprintf "TLS-HS: Asked to authorize a certificate twice"))
                | TLS.Handshaken conn -> wrapRead conn
                | TLS.Read (conn,msg) ->
                    let read = undoMsg_i conn msg in
                    if equalBytes read [||] then
                        // The other party sent some empty fragment. Let's read more.
                        wrapRead conn
                    else
                        (conn,read)
                | TLS.DontWrite conn -> wrapRead conn
            else
                TLS.refuse conn q
                raise (IOException(sprintf "TLS-HS: Asked to authorize a certificate"))
        | TLS.Handshaken conn -> wrapRead conn
        | TLS.Read (conn,msg) ->
            let read = undoMsg_i conn msg in
            if equalBytes read [||] then
                // The other party sent some empty fragment. Let's read more.
                wrapRead conn
            else
                (conn,read)
        | TLS.DontWrite conn -> wrapRead conn

    let mutable conn =
        let tcpStream = Tcp.create s
        let conn =
            match b with
            | TLSClient -> TLS.connect tcpStream options
            | TLSServer -> TLS.accept_connected tcpStream options
        doHS conn

    let rec wrapWrite conn msg =
        match TLS.write conn msg with
        | TLS.WriteError (adOpt,err) ->
            match adOpt with
            | None -> raise (IOException(sprintf "TLS-HS: Internal error: %A" err))
            | Some ad -> raise (IOException(sprintf "TLS-HS: Sent alert: %A %A" ad err))
        | TLS.WriteComplete conn -> conn
        | TLS.WritePartial (conn,msg) -> wrapWrite conn msg
        | TLS.MustRead conn ->
            let conn = doHS conn
            wrapWrite conn msg

    override this.get_CanRead()     = true
    override this.get_CanWrite()    = true
    override this.get_CanSeek()     = false
    override this.get_Length()      = raise (NotSupportedException())
    override this.SetLength(i)      = raise (NotSupportedException())
    override this.get_Position()    = raise (NotSupportedException())
    override this.set_Position(i)   = raise (NotSupportedException())
    override this.Seek(i,o)         = raise (NotSupportedException())

    override this.Flush() =
        if not (equalBytes outbuf [||]) then
            let msgO = doMsg_o conn outbuf
            conn <- wrapWrite conn msgO
            outbuf <- [||]

    override this.Read(buffer, offset, count) =
        let data =
            if equalBytes inbuf [||] then
                (* Read from the socket, and possibly buffer some data *)
                let (c,data) = wrapRead conn
                    // Fixme: is data is [||] we should set conn to "null" (which we cannot)
                conn <- c
                data
            else (* Use the buffer *)
                let tmp = inbuf in
                inbuf <- [||]
                tmp
        let l = length data in
        if l <= count then
            Array.blit data 0 buffer offset l
            l
        else
            let (recv,newBuf) = split data count in
            Array.blit recv 0 buffer offset count
            inbuf <- newBuf
            count

    override this.Write(buffer,offset,count) =
        let data = createBytes count 0 in
        Array.blit buffer offset data 0 count
        outbuf <- data
        this.Flush ()

    override this.Close() =
        this.Flush()
        if not closed then
            TLS.half_shutdown conn
            closed <- true
        if own then
            s.Close()
