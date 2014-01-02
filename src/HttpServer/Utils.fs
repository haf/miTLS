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

module Utils

open System
open System.IO
open System.Text.RegularExpressions
open System.Web
open Microsoft.FSharp.Reflection

(* ------------------------------------------------------------------------ *)
type String with
    member self.UrlDecode () = HttpUtility.UrlDecode(self)

(*
type Option<'T> with
    member self.oget = fun dfl ->
        match self with None -> dfl | Some x -> x
*)

(* ------------------------------------------------------------------------ *)
type Stream with
    member self.CopyTo (output : Stream, length : int64) : int64 =
        let (*---*) buffer   : byte[] = Array.zeroCreate (128 * 1024) in
        let mutable position : int64  = (int64 0) in
        let mutable eof      : bool   = false in
            while not eof && (position < length) do
                let remaining = min (int64 buffer.Length) (length - position) in
                let rr = self.Read(buffer, 0, int remaining) in
                    if rr = 0 then
                        eof <- true
                    else begin
                        output.Write(buffer, 0, rr);
                        position <- position + (int64 rr)
                    end
            done;
            position

(* ------------------------------------------------------------------------ *)
let noexn = fun cb ->
    try cb () with _ -> ()

(* ------------------------------------------------------------------------ *)
let unerror (x : 'a TLSError.Result) =
    match x with
    | Error.Error   _ -> failwith "Utils.unerror"
    | Error.Correct x -> x

(* ------------------------------------------------------------------------ *)
let (|Match|_|) pattern input =
    let re = System.Text.RegularExpressions.Regex(pattern)
    let m  = re.Match(input) in
        if   m.Success
        then Some (re.GetGroupNames()
                        |> Seq.map (fun n -> (n, m.Groups.[n]))
                        |> Seq.filter (fun (n, g) -> g.Success)
                        |> Seq.map (fun (n, g) -> (n, g.Value))
                        |> Map.ofSeq)
        else None

(* ------------------------------------------------------------------------ *)
module IO =
    let ReadAllLines (stream : StreamReader) = seq {
        while not stream.EndOfStream do
            yield stream.ReadLine ()
    }

(* ------------------------------------------------------------------------ *)
exception NotAValidEnumeration

let enumeration<'T> () =
    let t = typeof<'T>

    if not (FSharpType.IsUnion(t)) then
        raise NotAValidEnumeration;

    let cases = FSharpType.GetUnionCases(t)

    if not (Array.forall
                (fun (c : UnionCaseInfo) -> c.GetFields().Length = 0)
                (FSharpType.GetUnionCases(t))) then
        raise NotAValidEnumeration;

    let cases =
        Array.map
            (fun (c : UnionCaseInfo) ->
                (FSharpValue.MakeUnion(c, [||]) :?> 'T), c.Name)
            cases
    in
        cases
