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

module Alert

open Bytes
open Error
open TLSConstants
open TLSInfo
open Range

type pre_al_state = {
  al_incoming: bytes (* incomplete incoming message *)
  al_outgoing: bytes (* emptybstr if nothing to be sent *)
}

type state = pre_al_state

let init (ci:ConnectionInfo) = {al_incoming = [||]; al_outgoing = [||]}

type ALFragReply =
    | EmptyALFrag
    | ALFrag of range * HSFragment.plain
    | LastALFrag of range * HSFragment.plain * alertDescription
    | LastALCloseFrag of range * HSFragment.plain

type alert_reply =
    | ALAck of state
    | ALFatal of alertDescription * state
    | ALWarning of alertDescription * state
    | ALClose_notify of state

(* Conversions *)

let alertBytes ad =
  (* Severity (warning or fatal) is hardcoded, as specified in sec. 7.2.2 *)
  match ad with
    | AD_close_notify ->                       [|1uy;   0uy|]
    | AD_unexpected_message ->                 [|2uy;  10uy|]
    | AD_bad_record_mac ->                     [|2uy;  20uy|]
    | AD_decryption_failed ->                  [|2uy;  21uy|]
    | AD_record_overflow ->                    [|2uy;  22uy|]
    | AD_decompression_failure ->              [|2uy;  30uy|]
    | AD_handshake_failure ->                  [|2uy;  40uy|]
    | AD_no_certificate ->                     [|1uy;  41uy|]
    | AD_bad_certificate_warning ->            [|1uy;  42uy|]
    | AD_bad_certificate_fatal ->              [|2uy;  42uy|]
    | AD_unsupported_certificate_warning ->    [|1uy;  43uy|]
    | AD_unsupported_certificate_fatal ->      [|2uy;  43uy|]
    | AD_certificate_revoked_warning ->        [|1uy;  44uy|]
    | AD_certificate_revoked_fatal ->          [|2uy;  44uy|]
    | AD_certificate_expired_warning ->        [|1uy;  45uy|]
    | AD_certificate_expired_fatal ->          [|2uy;  45uy|]
    | AD_certificate_unknown_warning ->        [|1uy;  46uy|]
    | AD_certificate_unknown_fatal ->          [|2uy;  46uy|]
    | AD_illegal_parameter ->                  [|2uy;  47uy|]
    | AD_unknown_ca ->                         [|2uy;  48uy|]
    | AD_access_denied ->                      [|2uy;  49uy|]
    | AD_decode_error ->                       [|2uy;  50uy|]
    | AD_decrypt_error ->                      [|1uy;  51uy|]
    | AD_export_restriction ->                 [|2uy;  60uy|]
    | AD_protocol_version ->                   [|2uy;  70uy|]
    | AD_insufficient_security ->              [|2uy;  71uy|]
    | AD_internal_error ->                     [|2uy;  80uy|]
    | AD_user_cancelled_warning ->             [|1uy;  90uy|]
    | AD_user_cancelled_fatal ->               [|2uy;  90uy|]
    | AD_no_renegotiation ->                   [|1uy; 100uy|]
    | AD_unsupported_extension ->              [|2uy; 110uy|]

let parseAlert b =
    match b with
    | [|1uy;   0uy|] -> correct(AD_close_notify                         )
    | [|2uy;  10uy|] -> correct(AD_unexpected_message                   )
    | [|2uy;  20uy|] -> correct(AD_bad_record_mac                       )
    | [|2uy;  21uy|] -> correct(AD_decryption_failed                    )
    | [|2uy;  22uy|] -> correct(AD_record_overflow                      )
    | [|2uy;  30uy|] -> correct(AD_decompression_failure                )
    | [|2uy;  40uy|] -> correct(AD_handshake_failure                    )
    | [|1uy;  41uy|] -> correct(AD_no_certificate                       )
    | [|1uy;  42uy|] -> correct(AD_bad_certificate_warning              )
    | [|2uy;  42uy|] -> correct(AD_bad_certificate_fatal                )
    | [|1uy;  43uy|] -> correct(AD_unsupported_certificate_warning      )
    | [|2uy;  43uy|] -> correct(AD_unsupported_certificate_fatal        )
    | [|1uy;  44uy|] -> correct(AD_certificate_revoked_warning          )
    | [|2uy;  44uy|] -> correct(AD_certificate_revoked_fatal            )
    | [|1uy;  45uy|] -> correct(AD_certificate_expired_warning          )
    | [|2uy;  45uy|] -> correct(AD_certificate_expired_fatal            )
    | [|1uy;  46uy|] -> correct(AD_certificate_unknown_warning          )
    | [|2uy;  46uy|] -> correct(AD_certificate_unknown_fatal            )
    | [|2uy;  47uy|] -> correct(AD_illegal_parameter                    )
    | [|2uy;  48uy|] -> correct(AD_unknown_ca                           )
    | [|2uy;  49uy|] -> correct(AD_access_denied                        )
    | [|2uy;  50uy|] -> correct(AD_decode_error                         )
    | [|1uy;  51uy|] -> correct(AD_decrypt_error                        )
    | [|2uy;  60uy|] -> correct(AD_export_restriction                   )
    | [|2uy;  70uy|] -> correct(AD_protocol_version                     )
    | [|2uy;  71uy|] -> correct(AD_insufficient_security                )
    | [|2uy;  80uy|] -> correct(AD_internal_error                       )
    | [|1uy;  90uy|] -> correct(AD_user_cancelled_warning               )
    | [|2uy;  90uy|] -> correct(AD_user_cancelled_fatal                 )
    | [|1uy; 100uy|] -> correct(AD_no_renegotiation                     )
    | [|2uy; 110uy|] -> correct(AD_unsupported_extension                )
    | _ -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let isFatal ad =
    match ad with
    | AD_unexpected_message
    | AD_bad_record_mac
    | AD_decryption_failed
    | AD_record_overflow
    | AD_decompression_failure
    | AD_handshake_failure
    | AD_bad_certificate_fatal
    | AD_unsupported_certificate_fatal
    | AD_certificate_revoked_fatal
    | AD_certificate_expired_fatal
    | AD_certificate_unknown_fatal
    | AD_illegal_parameter
    | AD_unknown_ca
    | AD_access_denied
    | AD_decode_error
    | AD_export_restriction
    | AD_protocol_version
    | AD_insufficient_security
    | AD_internal_error
    | AD_user_cancelled_fatal
    | AD_unsupported_extension -> true
    | _ -> false

let send_alert (ci:ConnectionInfo) state alertDesc =

    (* Note: we only support sending one alert in the whole protocol execution
       (because we'll tell dispatch an alert has been sent when the buffer gets empty)
       So we only add an alert on an empty buffer (we don't enqueue more alerts) *)
    if equalBytes state.al_outgoing [||] then
        {state with al_outgoing = alertBytes alertDesc}
    else
        state (* Just ignore the request *)

// We implement locally fragmentation, not hiding any length
let makeFragment ki b =
    let (b0,rem) = if length b < fragmentLength then (b,[||])
                   else Bytes.split b fragmentLength
    let r0 = (length b0, length b0) in
    let f = HSFragment.fragmentPlain ki r0 b0 in
    ((r0,f),rem)

let next_fragment ci state =
    match state.al_outgoing with
    | [||] ->
        (EmptyALFrag, state)
    | d ->
        let ((r0,df),rem) = makeFragment ci.id_out d in
        let state = {state with al_outgoing = rem} in
        match rem with
        | [||] ->

            match parseAlert d with
            | Error(x,y) -> unexpectedError ("[next_fragment] This invocation of parseAlertDescription should never fail")
            | Correct(ad) ->
                match ad with
                | AD_close_notify -> (LastALCloseFrag(r0,df),state)
                | _ -> (LastALFrag(r0,df,ad),state)
        | _ -> (ALFrag(r0,df),state)

let handle_alert ci state alDesc =
    match alDesc with
    | AD_close_notify ->
        (* we possibly send a close_notify back *)
        let state = send_alert ci state AD_close_notify in
        ALClose_notify (state)
    | _ ->
        if isFatal alDesc then
            ALFatal (alDesc,state)
        else
            ALWarning (alDesc,state)

let recv_fragment (ci:ConnectionInfo) state (r:range) (f:HSFragment.fragment) =

    let fragment = HSFragment.fragmentRepr ci.id_in r f in
    match state.al_incoming with
    | [||] ->
        (* Empty buffer *)
        match length fragment with
        | 0 -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Empty alert fragments are invalid")
        | 1 -> Correct (ALAck ({state with al_incoming = fragment})) (* Buffer this partial alert *)
        | _ -> (* Full alert received *)
            let (al,rem) = Bytes.split fragment 2 in
            if length rem <> 0 then (* Check there are no more data *)
                Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "No more data are expected after an alert")
            else
                match parseAlert al with
                | Error(x,y) -> Error(x,y)
                | Correct(alert) -> let res = handle_alert ci state alert in correct(res)
    | inc ->
        match length fragment with
        | 0 -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Empty alert fragments are invalid")
        | _ ->
            let (part2,rem) = Bytes.split fragment 1 in
            if length rem <> 0 then (* Check there are no more data *)
                Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "No more data are expected after an alert")
            else
                let bmsg = inc @| part2 in
                match parseAlert bmsg with
                | Error(x,y) -> Error(x,y)
                | Correct(alert) ->
                    let state = {state with al_incoming = [||] } in
                    let res = handle_alert ci state alert in
                    correct(res)

let is_incoming_empty (c:ConnectionInfo) s = equalBytes s.al_incoming [||]

let reset_incoming (c:ConnectionInfo) s (nc:ConnectionInfo) =
    {s with al_incoming = [||]}

let reset_outgoing (c:ConnectionInfo) s (nc:ConnectionInfo) =
    {s with al_outgoing = [||]}
