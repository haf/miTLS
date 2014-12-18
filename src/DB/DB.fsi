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

type db

exception DBError of string

val opendb  : string -> db
val closedb : db -> unit
val put     : db -> byte[] -> byte[] -> unit
val get     : db -> byte[] -> byte[] option
val remove  : db -> byte[] -> bool
val all     : db -> (byte[] * byte[]) list
val keys    : db -> byte[] list
val tx      : db -> (db -> 'a) -> 'a
