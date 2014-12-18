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

module HttpLogger

open System
open System.Threading

type level = DEBUG | INFO | ERROR

type HttpLogger () =
    static let mutable loglevel : level = INFO

    static member private lock = new Object ()

    static member Level
        with get ()       = loglevel
        and  set newlevel = loglevel <- newlevel;

    static member private WriteLine (s : string) =
        lock HttpLogger.lock (fun () -> Console.WriteLine(s))

    static member Log level message =
        if level >= loglevel then begin
            HttpLogger.WriteLine
                (sprintf "[Thread %4d] [%A] %s"
                    Thread.CurrentThread.ManagedThreadId
                    DateTime.Now
                    message)
        end

    static member Debug message =
        HttpLogger.Log DEBUG message

    static member Info message =
        HttpLogger.Log INFO message

    static member Error message =
        HttpLogger.Log ERROR message
