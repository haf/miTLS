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

module Bytes

type nat = int
type bytes = byte[]

let length (d:bytes) = d.Length
type lbytes = bytes

let createBytes len (value:int) : bytes =
    try Array.create len (byte value)
    with :? System.OverflowException -> failwith "Default integer for createBytes was greater than max_value"

let bytes_of_int nb i =
  let rec put_bytes bb lb n =
    if lb = 0 then failwith "not enough bytes"
    else
      begin
        Array.set bb (lb-1) (byte (n%256));
        if n/256 > 0 then
          put_bytes bb (lb-1) (n/256)
        else bb
      end
  in
  let b = Array.zeroCreate nb in
    put_bytes b nb i

let int_of_bytes (b:bytes) : int =
    List.fold (fun x y -> 256 * x + y) 0 (List.map (int) (Array.toList b))

//@ Constant time comparison (to mitigate timing attacks)
//@ The number of byte comparisons depends only on the lengths of both arrays.
let equalBytes (b1:bytes) (b2:bytes) =
    length b1 = length b2 &&
    Array.fold2 (fun ok x y -> x = y && ok) true b1 b2

let (@|) (a:bytes) (b:bytes) = Array.append a b
let split (b:bytes) i : bytes * bytes =
  Array.sub b 0 i,
  Array.sub b i (b.Length-i)
let split2 (b:bytes) i j : bytes * bytes * bytes =
  Array.sub b 0 i,
  Array.sub b i j,
  Array.sub b (i+j) (b.Length-(i+j))

let utf8 (x:string) : bytes = System.Text.Encoding.UTF8.GetBytes x
let iutf8 (x:bytes) : string = System.Text.Encoding.UTF8.GetString x

(* Time spans *)
type DateTime = DT of System.DateTime
type TimeSpan = TS of System.TimeSpan
let now () = DT (System.DateTime.Now)
let newTimeSpan h d m s = TS (new System.TimeSpan(h,d,m,s))
let addTimeSpan (DT(a)) (TS(b)) = DT (a + b)
let greaterDateTime (DT(a)) (DT(b)) = a > b

(* List operation functions. Currently only used by the Handshake. *)
let fold (op: bytes-> bytes-> bytes) state data = List.fold op state data
let filter f l = List.filter f l
let foldBack (f:bytes -> bytes -> bytes) bl s = List.foldBack f bl s
let exists f l = List.exists f l
let memr l x = List.exists (fun y -> x = y) l
let choose f l = List.choose f l
let tryFind f l = List.tryFind f l
#if ideal
let find f l = List.find f l

let rec assoc f l =
    match l with
      | (f',l')::_ when f=f' -> Some (f)
      | _::l                   -> assoc f l
      | []                       -> None
let rec assoc2_1 (f1,f2) l =
    match l with
      | (f1',f2',v)::_ when f1=f1' && f2=f2' -> Some (v)
      | _::l                   -> assoc2_1 (f1,f2) l
      | []                       -> None

let mem x l = List.exists (fun y -> x = y) l
#endif
let listLength (l:'a list) = l.Length
let listHead (l:'a list) = l.Head

let isSome (l:'a option) =
  match l with
      Some(x) -> true
    | None -> false
