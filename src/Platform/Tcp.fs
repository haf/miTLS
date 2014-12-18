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

module Tcp

open System.Net
open System.Net.Sockets
open Bytes
open Error

type NetworkStream = N of System.IO.Stream
type TcpListener = T of System.Net.Sockets.TcpListener

let create s = N(s)

(* Server side *)

let listen addr port =
    let tcpList = new System.Net.Sockets.TcpListener(IPAddress.Parse(addr),port) in
    tcpList.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
    tcpList.Start();
    T tcpList

let acceptTimeout timeout (T tcpList) =
    let client = tcpList.AcceptTcpClient() in
    client.ReceiveTimeout <- timeout;
    client.SendTimeout <- timeout;
    N (client.GetStream())

let accept t =
    acceptTimeout 0 t

let stop (T tcpList) =
    tcpList.Stop()

(* Client side *)

let connectTimeout timeout addr port =
    let tcpCl = new TcpClient(addr,port) in
    tcpCl.ReceiveTimeout <- timeout;
    tcpCl.SendTimeout <- timeout;
    N (tcpCl.GetStream())

let connect addr port =
    connectTimeout 0 addr port

(* Input/Output *)

let rec read_acc (N ns) nbytes prev =
    if nbytes = 0 then
        Correct (abytes prev)
    else
        try
            let buf = Array.zeroCreate nbytes in
            let read = ns.Read (buf, 0, nbytes) in
            if read = 0 then
                Error(perror __SOURCE_FILE__ __LINE__ "TCP connection closed")
            else
                let rem = nbytes - read in
                read_acc (N ns) rem (Array.append prev (Array.sub buf 0 read))
        with
            | _ -> Error(perror __SOURCE_FILE__ __LINE__ "TCP connection closed")

let read (N ns) nbytes =
    try
        (read_acc (N ns) nbytes (Array.zeroCreate 0))
    with
        | _ -> Error (perror __SOURCE_FILE__ __LINE__ "TCP connection closed")

let write (N ns) content =
    try
        let content = cbytes content in
        Correct (ns.Write (content, 0, content.Length))
    with
        | _ -> Error (perror __SOURCE_FILE__ __LINE__ "TCP connection closed")

let close (N ns) =
    ns.Close()
