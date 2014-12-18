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

type options = {
    ciphersuite   : TLSConstants.cipherSuiteName list;
    tlsminversion : TLSConstants.ProtocolVersion;
    tlsmaxversion : TLSConstants.ProtocolVersion;
    servername    : string;
    clientname    : string option;
    localaddr     : System.Net.IPEndPoint;
    sessiondir    : string;
    dhdir         : string;
}

val client : options -> unit
val server : options -> unit
