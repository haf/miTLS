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

module PwAppRun

open System
open System.Threading

let servname = "mitls.example.org"
let my       = "xxxxxxxxxxxxxxxx"
let token    = PwToken.create ()
let _        = PwToken.register my token

let server () =
    try
        printfn "S: %A" (PwApp.response servname)
    with e ->
        printfn "E: %A" e

let client () =
    let r = (PwApp.request servname my token) in
        printfn "C: %A" r

let program () =
    let tserver = new Thread(new ThreadStart(server))

    tserver.Name <- "Server"; tserver.Start ()
    Thread.Sleep 1000; client ();
    Thread.Sleep -1

let _ =
    program ()
