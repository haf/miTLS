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

module EchoImpl

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading

(* ------------------------------------------------------------------------ *)
type options = {
    ciphersuite   : TLSConstants.cipherSuiteName list;
    tlsminversion : TLSConstants.ProtocolVersion;
    tlsmaxversion : TLSConstants.ProtocolVersion;
    servername    : string;
    clientname    : string option;
    localaddr     : IPEndPoint;
    sessiondir    : string;
    dhdir         : string;
}

(* ------------------------------------------------------------------------ *)
let noexn = fun cb ->
    try cb () with _ -> ()

(* ------------------------------------------------------------------------ *)
let tlsoptions (options : options) = {
    TLSInfo.minVer = options.tlsminversion
    TLSInfo.maxVer = options.tlsmaxversion

    TLSInfo.ciphersuites = TLSConstants.cipherSuites_of_nameList options.ciphersuite

    TLSInfo.compressions = [ TLSConstants.NullCompression ]

    TLSInfo.honourHelloReq = TLSInfo.HRPResume
    TLSInfo.allowAnonCipherSuite = false
    TLSInfo.check_client_version_in_pms_for_old_tls = true
    TLSInfo.request_client_certificate = options.clientname.IsSome

    TLSInfo.safe_renegotiation = true
    TLSInfo.safe_resumption = false

    TLSInfo.server_name = options.servername
    TLSInfo.client_name = match options.clientname with None -> "" | Some x -> x

    TLSInfo.sessionDBFileName = Path.Combine(options.sessiondir, "sessionDBFile.bin")
    TLSInfo.sessionDBExpiry   = Date.newTimeSpan 1 0 0 0 (* one day *)

    TLSInfo.dhDBFileName = Path.Combine(options.dhdir, "dhparams-db.bin")
    TLSInfo.dhDefaultGroupFileName = Path.Combine(options.dhdir, "default-dh.pem")
    TLSInfo.dhPQMinLength = TLSInfo.defaultConfig.dhPQMinLength
}

(* ------------------------------------------------------------------------ *)
let client_handler ctxt (peer : Socket) = fun () ->
    use peer     = peer
    let endpoint = peer.RemoteEndPoint

    fprintfn stderr "Connect: %s" (endpoint.ToString ());
    try
        try
            use netstream = new NetworkStream (peer, false)
            use tlsstream = new TLStream.TLStream
                              (netstream, ctxt, TLStream.TLSServer, false)

            Console.Error.WriteLine((tlsstream.GetSessionInfoString()));

            let reader    = new StreamReader (tlsstream)
            let writer    = new StreamWriter (tlsstream)

            let rec doit () =
                let line = reader.ReadLine ()

                if line <> null then
                    fprintfn stderr "Line[%s]: %s" (endpoint.ToString()) line
                    writer.WriteLine (line)
                    writer.Flush ()
                    doit ()
            in
                doit ()
        with e ->
            fprintfn stderr "%s" (e.ToString ())
    finally
        fprintfn stderr "Disconnect: %s" (endpoint.ToString ());

(* ------------------------------------------------------------------------ *)
let server (options : options) =
    let ctxt     = tlsoptions options
    let listener = new TcpListener(options.localaddr)

    try
        listener.Start ();
        listener.Server.SetSocketOption(SocketOptionLevel.Socket,
                                        SocketOptionName.ReuseAddress,
                                        true);
        while true do
            let peer = listener.AcceptSocket () in
                try
                    let thread = new Thread(new ThreadStart(client_handler ctxt peer)) in
                        thread.IsBackground <- true;
                        thread.Start()
                with
                | :? IOException as e ->
                    noexn (fun () -> peer.Close())
                    Console.WriteLine(e.Message)
                | e ->
                    noexn (fun () -> peer.Close())
                    raise e
        done
    finally
        listener.Stop ()

(* ------------------------------------------------------------------------ *)
let client (options : options) =
    let ctxt   = tlsoptions options
    use socket = new TcpClient()

    socket.Connect(options.localaddr)

    use tlsstream = new TLStream.TLStream(socket.GetStream(), ctxt, TLStream.TLSClient)

    Console.Error.WriteLine((tlsstream.GetSessionInfoString()));

    let reader = new StreamReader (tlsstream)
    let writer = new StreamWriter (tlsstream)

    let rec doit () =
        let line = System.Console.ReadLine ()

        if line <> null then
            writer.WriteLine(line); writer.Flush ()
            Console.WriteLine(reader.ReadLine ())
            doit ()
    in
        doit ()
