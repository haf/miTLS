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

#light "off"

module TLSError

type alertDescription =
    | AD_close_notify
    | AD_unexpected_message
    | AD_bad_record_mac
    | AD_decryption_failed
    | AD_record_overflow
    | AD_decompression_failure
    | AD_handshake_failure
    | AD_no_certificate
    | AD_bad_certificate_warning
    | AD_bad_certificate_fatal
    | AD_unsupported_certificate_warning
    | AD_unsupported_certificate_fatal
    | AD_certificate_revoked_warning
    | AD_certificate_revoked_fatal
    | AD_certificate_expired_warning
    | AD_certificate_expired_fatal
    | AD_certificate_unknown_warning
    | AD_certificate_unknown_fatal
    | AD_illegal_parameter
    | AD_unknown_ca
    | AD_access_denied
    | AD_decode_error
    | AD_decrypt_error
    | AD_export_restriction
    | AD_protocol_version
    | AD_insufficient_security
    | AD_internal_error
    | AD_user_cancelled_warning
    | AD_user_cancelled_fatal
    | AD_no_renegotiation
    | AD_unsupported_extension

type Result<'a> = Error.optResult<alertDescription * string,'a>
