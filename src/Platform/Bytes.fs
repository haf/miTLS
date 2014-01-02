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
type cbytes = byte[]

let rec getByte (bl:byte[] list) (i:int) =
    match bl with
     [] -> failwith "getByte: array out of bounds"
   | h::t when i >= h.Length -> getByte t (i-h.Length)
   | h::t -> Array.get h i

let rec getByte2 (bl: byte[] list) i : byte*byte =
    match bl with
     [] -> failwith "array out of bounds"
   | h::t when i >= h.Length -> getByte2 t (i - h.Length)
   | h::t when h.Length - i >= 2 -> Array.get h i, Array.get h (i+1)
   | h1::h2::t when h1.Length - i = 1 && h2.Length > 0 -> Array.get h1 i, Array.get h2 0
   | _ -> failwith "getByte2: array out of bounds"

let rec getBytes (bl:byte[] list) i n  =
    match bl with
     [] -> if n > 0 then failwith "getBytes: array out of bounds" else [||]
   | h::t ->
        if i >= h.Length
        then getBytes t (i-h.Length) n
        else let curr = h.Length - i in
             if curr >= n
             then Array.sub h i n
             else Array.append (Array.sub h i curr) (getBytes t 0 (n-curr))

//@ Constant time comparison (to mitigate timing attacks)
//@ The number of byte comparisons depends only on the lengths of both arrays.
let equalCBytes (b1:byte[]) (b2:byte[]) =
    b1.Length = b2.Length &&
    Array.fold2 (fun ok x y -> x = y && ok) true (b1) (b2)

(* Original implementation of bytes *)
[<CustomEquality;NoComparison>]
type bytes =
     {b:byte[]}
     override x.Equals(y) = (match y with :? bytes as y -> x.b = y.b | _ -> false)
     override x.GetHashCode() = hash x

let length (d:bytes) = (d.b).Length
let abytes (b:byte[]) = {b=b}
let abytes_max b = abytes b
let abyte (b:byte) = {b=[|b|]}
let abyte2 (b1,b2) = {b=[|b1;b2|]}
let cbytes (b:bytes) = b.b
let cbyte (b:bytes) = if length b = 1 then b.b.[0] else failwith "cbyte invoked on bytes of length <> 1"
let cbyte2 (b:bytes) = if length b = 2 then (b.b.[0],b.b.[1]) else failwith "cbyte invoked on bytes of length <> 2"

let (@|) (a:bytes) (b:bytes) = abytes(Array.append (cbytes a) (cbytes b))
let split (b:bytes) i : bytes * bytes =
  abytes (Array.sub (cbytes b) 0 i),
  abytes (Array.sub (cbytes b) i ((length b) - i))

let empty_bytes = abytes [||]
let createBytes len (value:int) : bytes =
    try abytes (Array.create len (byte value))
    with :? System.OverflowException -> failwith "Default integer for createBytes was greater than max_value"

type lbytes = bytes

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
    abytes(put_bytes b nb i)

let int_of_bytes (b:bytes) : int =
    Microsoft.FSharp.Collections.List.fold (fun x y -> 256 * x + y) 0 (Microsoft.FSharp.Collections.List.map (int) (Array.toList (cbytes b)))

//@ Constant time comparison (to mitigate timing attacks)
//@ The number of byte comparisons depends only on the lengths of both arrays.
let equalBytes (b1:bytes) (b2:bytes) =
    length b1 = length b2 &&
    Array.fold2 (fun ok x y -> x = y && ok) true (cbytes b1) (cbytes b2)

let xor s1 s2 nb =
  let s1 = cbytes s1 in
  let s2 = cbytes s2 in
  if Array.length s1 < nb || Array.length s2 < nb then
    Error.unexpected "[xor] arrays too short"
  else
    let res = Array.zeroCreate nb in
    for i=0 to nb-1 do
      res.[i] <- byte (int s1.[i] ^^^ int s2.[i])
    done;
    abytes res

let split2 (b:bytes) i j : bytes * bytes * bytes =
  let b1,b2 = split b i in
  let b2a,b2b = split b2 j in
  (b1,b2a,b2b)

let utf8 (x:string) : bytes = abytes (System.Text.Encoding.UTF8.GetBytes x)
let iutf8 (x:bytes) : string = System.Text.Encoding.UTF8.GetString (cbytes x)

let todo (s:string) : unit =
#if ideal
  failwith s
#else
  ()
#endif
