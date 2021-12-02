use ::libc;
use crate::gsasl::consts::*;

extern "C" {
    fn bindtextdomain(__domainname: *const libc::c_char,
                      __dirname: *const libc::c_char) -> *mut libc::c_char;
    fn dcgettext(__domainname: *const libc::c_char,
                 __msgid: *const libc::c_char, __category: libc::c_int)
     -> *mut libc::c_char;
}
/* *INDENT-OFF* */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub rc: libc::c_int,
    pub name: *const libc::c_char,
    pub description: *const libc::c_char,
}
static mut errors: [C2RustUnnamed_0; 69] =
    [{
         let mut init =
             C2RustUnnamed_0{rc: GSASL_OK as libc::c_int,
                             name:
                                 b"GSASL_OK\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Libgsasl success\x00" as *const u8 as
                                     *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NEEDS_MORE as libc::c_int,
                             name:
                                 b"GSASL_NEEDS_MORE\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"SASL mechanism needs more data\x00" as
                                     *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_UNKNOWN_MECHANISM as libc::c_int,
                             name:
                                 b"GSASL_UNKNOWN_MECHANISM\x00" as *const u8
                                     as *const libc::c_char,
                             description:
                                 b"Unknown SASL mechanism\x00" as *const u8 as
                                     *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_MECHANISM_CALLED_TOO_MANY_TIMES as
                                     libc::c_int,
                             name:
                                 b"GSASL_MECHANISM_CALLED_TOO_MANY_TIMES\x00"
                                     as *const u8 as *const libc::c_char,
                             description:
                                 b"SASL mechanism called too many times\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 4 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 5 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 6 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_MALLOC_ERROR as libc::c_int,
                             name:
                                 b"GSASL_MALLOC_ERROR\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Memory allocation error in SASL library\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_BASE64_ERROR as libc::c_int,
                             name:
                                 b"GSASL_BASE64_ERROR\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Base 64 coding error in SASL library\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_CRYPTO_ERROR as libc::c_int,
                             name:
                                 b"GSASL_CRYPTO_ERROR\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Low-level crypto error in SASL library\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 10 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 11 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 12 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 13 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 14 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 15 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 16 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 17 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 18 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 19 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 20 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 21 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 22 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 23 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 24 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 25 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 26 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 27 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 28 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_SASLPREP_ERROR as libc::c_int,
                             name:
                                 b"GSASL_SASLPREP_ERROR\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Could not prepare internationalized (non-ASCII) string.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_MECHANISM_PARSE_ERROR as libc::c_int,
                             name:
                                 b"GSASL_MECHANISM_PARSE_ERROR\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"SASL mechanism could not parse input\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_AUTHENTICATION_ERROR as libc::c_int,
                             name:
                                 b"GSASL_AUTHENTICATION_ERROR\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"Error authenticating user\x00" as *const u8
                                     as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 32 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_INTEGRITY_ERROR as libc::c_int,
                             name:
                                 b"GSASL_INTEGRITY_ERROR\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Integrity error in application payload\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 34 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_CLIENT_CODE as libc::c_int,
                             name:
                                 b"GSASL_NO_CLIENT_CODE\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Client-side functionality not available in library (application error)\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_SERVER_CODE as libc::c_int,
                             name:
                                 b"GSASL_NO_SERVER_CODE\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Server-side functionality not available in library (application error)\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_RELEASE_BUFFER_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_RELEASE_BUFFER_ERROR\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI library could not deallocate memory in gss_release_buffer() in SASL library.  This is a serious internal error.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_IMPORT_NAME_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_IMPORT_NAME_ERROR\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI library could not understand a peer name in gss_import_name() in SASL library.  This is most likely due to incorrect service and/or hostnames.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error in client while negotiating security context in gss_init_sec_context() in SASL library.  This is most likely due insufficient credentials or malicious interactions.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR\x00"
                                     as *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error in server while negotiating security context in gss_accept_sec_context() in SASL library.  This is most likely due insufficient credentials or malicious interactions.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_GSSAPI_UNWRAP_ERROR as libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_UNWRAP_ERROR\x00" as *const u8
                                     as *const libc::c_char,
                             description:
                                 b"GSSAPI error while decrypting or decoding data in gss_unwrap() in SASL library.  This is most likely due to data corruption.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_GSSAPI_WRAP_ERROR as libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_WRAP_ERROR\x00" as *const u8
                                     as *const libc::c_char,
                             description:
                                 b"GSSAPI error while encrypting or encoding data in gss_wrap() in SASL library.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_ACQUIRE_CRED_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_ACQUIRE_CRED_ERROR\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error acquiring credentials in gss_acquire_cred() in SASL library.  This is most likely due to not having the proper Kerberos key available in /etc/krb5.keytab on the server.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_DISPLAY_NAME_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_DISPLAY_NAME_ERROR\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error creating a display name denoting the client in gss_display_name() in SASL library.  This is probably because the client supplied bad data.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR\x00"
                                     as *const u8 as *const libc::c_char,
                             description:
                                 b"Other entity requested integrity or confidentiality protection in GSSAPI mechanism but this is currently not implemented.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 46 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 47 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE
                                     as libc::c_int,
                             name:
                                 b"GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE\x00"
                                     as *const u8 as *const libc::c_char,
                             description:
                                 b"SecurID needs additional passcode.\x00" as
                                     *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_SECURID_SERVER_NEED_NEW_PIN as
                                     libc::c_int,
                             name:
                                 b"GSASL_SECURID_SERVER_NEED_NEW_PIN\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"SecurID needs new pin.\x00" as *const u8 as
                                     *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: 50 as libc::c_int,
                             name: 0 as *const libc::c_char,
                             description: 0 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_CALLBACK as libc::c_int,
                             name:
                                 b"GSASL_NO_CALLBACK\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"No callback specified by caller (application error).\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_ANONYMOUS_TOKEN as libc::c_int,
                             name:
                                 b"GSASL_NO_ANONYMOUS_TOKEN\x00" as *const u8
                                     as *const libc::c_char,
                             description:
                                 b"Authentication failed because the anonymous token was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_AUTHID as libc::c_int,
                             name:
                                 b"GSASL_NO_AUTHID\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Authentication failed because the authentication identity was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_AUTHZID as libc::c_int,
                             name:
                                 b"GSASL_NO_AUTHZID\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Authentication failed because the authorization identity was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_PASSWORD as libc::c_int,
                             name:
                                 b"GSASL_NO_PASSWORD\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Authentication failed because the password was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_PASSCODE as libc::c_int,
                             name:
                                 b"GSASL_NO_PASSCODE\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Authentication failed because the passcode was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_PIN as libc::c_int,
                             name:
                                 b"GSASL_NO_PIN\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Authentication failed because the pin code was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_SERVICE as libc::c_int,
                             name:
                                 b"GSASL_NO_SERVICE\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Authentication failed because the service name was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_HOSTNAME as libc::c_int,
                             name:
                                 b"GSASL_NO_HOSTNAME\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Authentication failed because the host name was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR\x00"
                                     as *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error encapsulating token.\x00" as
                                     *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR\x00"
                                     as *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error decapsulating token.\x00" as
                                     *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR
                                     as libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR\x00"
                                     as *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error getting OID for SASL mechanism name.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR\x00"
                                     as *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error testing for OID in OID set.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_GSSAPI_RELEASE_OID_SET_ERROR as
                                     libc::c_int,
                             name:
                                 b"GSASL_GSSAPI_RELEASE_OID_SET_ERROR\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"GSSAPI error releasing OID set.\x00" as
                                     *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_CB_TLS_UNIQUE as libc::c_int,
                             name:
                                 b"GSASL_NO_CB_TLS_UNIQUE\x00" as *const u8 as
                                     *const libc::c_char,
                             description:
                                 b"Authentication failed because a tls-unique CB was not provided.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_NO_SAML20_IDP_IDENTIFIER as
                                     libc::c_int,
                             name:
                                 b"GSASL_NO_SAML20_IDP_IDENTIFIER\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"Callback failed to provide SAML20 IdP identifier.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc: GSASL_NO_SAML20_REDIRECT_URL as libc::c_int,
                             name:
                                 b"GSASL_NO_SAML20_REDIRECT_URL\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"Callback failed to provide SAML20 redirect URL.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     },
     {
         let mut init =
             C2RustUnnamed_0{rc:
                                 GSASL_NO_OPENID20_REDIRECT_URL as
                                     libc::c_int,
                             name:
                                 b"GSASL_NO_OPENID20_REDIRECT_URL\x00" as
                                     *const u8 as *const libc::c_char,
                             description:
                                 b"Callback failed to provide OPENID20 redirect URL.\x00"
                                     as *const u8 as *const libc::c_char,};
         init
     }];
/* *INDENT-ON* */
/* *
 * gsasl_strerror:
 * @err: libgsasl error code
 *
 * Convert return code to human readable string explanation of the
 * reason for the particular error code.
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * This function is one of few in the library that can be used without
 * a successful call to gsasl_init().
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing an explanation of the error code @err.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_strerror(mut err: libc::c_int)
 -> *const libc::c_char {
    static mut unknown: *const libc::c_char =
        b"Libgsasl unknown error\x00" as *const u8 as *const libc::c_char;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    bindtextdomain(b"gsasl\x00" as *const u8 as *const libc::c_char,
                   b"/usr/local/share/locale\x00" as *const u8 as
                       *const libc::c_char);
    if err < 0 as libc::c_int ||
           err >=
               (::std::mem::size_of::<[C2RustUnnamed_0; 69]>() as
                    libc::c_ulong).wrapping_div(::std::mem::size_of::<C2RustUnnamed_0>()
                                                    as libc::c_ulong) as
                   libc::c_int {
        return dcgettext(b"gsasl\x00" as *const u8 as *const libc::c_char,
                         unknown, 5 as libc::c_int)
    }
    p = errors[err as usize].description;
    if p.is_null() { p = unknown }
    return dcgettext(b"gsasl\x00" as *const u8 as *const libc::c_char, p,
                     5 as libc::c_int);
}
/* gsasl.h --- Header file for GNU SASL Library.
 * Copyright (C) 2002-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
/* *
 * SECTION:gsasl
 * @title: gsasl.h
 * @short_description: main library interfaces
 *
 * The main library interfaces are declared in gsasl.h.
 */
/* size_t */
/* Get version symbols. */
/* *
 * GSASL_API:
 *
 * Symbol holding shared library API visibility decorator.
 *
 * This is used internally by the library header file and should never
 * be used or modified by the application.
 *
 * https://www.gnu.org/software/gnulib/manual/html_node/Exported-Symbols-of-Shared-Libraries.html
 */
/* RFC 2222: SASL mechanisms are named by strings, from 1 to 20
   * characters in length, consisting of upper-case letters, digits,
   * hyphens, and/or underscores.  SASL mechanism names must be
   * registered with the IANA.
   */
/* *
   * Gsasl_rc:
   * @GSASL_OK: Successful return code, guaranteed to be always 0.
   * @GSASL_NEEDS_MORE: Mechanism expects another round-trip.
   * @GSASL_UNKNOWN_MECHANISM: Application requested an unknown mechanism.
   * @GSASL_MECHANISM_CALLED_TOO_MANY_TIMES: Application requested too
   *   many round trips from mechanism.
   * @GSASL_MALLOC_ERROR: Memory allocation failed.
   * @GSASL_BASE64_ERROR: Base64 encoding/decoding failed.
   * @GSASL_CRYPTO_ERROR: Cryptographic error.
   * @GSASL_SASLPREP_ERROR: Failed to prepare internationalized string.
   * @GSASL_MECHANISM_PARSE_ERROR: Mechanism could not parse input.
   * @GSASL_AUTHENTICATION_ERROR: Authentication has failed.
   * @GSASL_INTEGRITY_ERROR: Application data integrity check failed.
   * @GSASL_NO_CLIENT_CODE: Library was built with client functionality.
   * @GSASL_NO_SERVER_CODE: Library was built with server functionality.
   * @GSASL_NO_CALLBACK: Application did not provide a callback.
   * @GSASL_NO_ANONYMOUS_TOKEN: Could not get required anonymous token.
   * @GSASL_NO_AUTHID: Could not get required authentication
   *   identity (username).
   * @GSASL_NO_AUTHZID: Could not get required authorization identity.
   * @GSASL_NO_PASSWORD: Could not get required password.
   * @GSASL_NO_PASSCODE: Could not get required SecurID PIN.
   * @GSASL_NO_PIN: Could not get required SecurID PIN.
   * @GSASL_NO_SERVICE: Could not get required service name.
   * @GSASL_NO_HOSTNAME: Could not get required hostname.
   * @GSASL_NO_CB_TLS_UNIQUE: Could not get required tls-unique CB.
   * @GSASL_NO_SAML20_IDP_IDENTIFIER: Could not get required SAML IdP.
   * @GSASL_NO_SAML20_REDIRECT_URL: Could not get required SAML
   *   redirect URL.
   * @GSASL_NO_OPENID20_REDIRECT_URL: Could not get required OpenID
   *   redirect URL.
   * @GSASL_GSSAPI_RELEASE_BUFFER_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_IMPORT_NAME_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_UNWRAP_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_WRAP_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_ACQUIRE_CRED_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_DISPLAY_NAME_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR: An unsupported
   *   quality-of-protection layer was requeted.
   * @GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR: GSS-API library call error.
   * @GSASL_GSSAPI_RELEASE_OID_SET_ERROR: GSS-API library call error.
   * @GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE: SecurID mechanism
   *   needs an additional passcode.
   * @GSASL_SECURID_SERVER_NEED_NEW_PIN: SecurID mechanism
   *   needs an new PIN.
   *
   * Error codes for library functions.
   */
/* Mechanism specific errors. */
/* When adding new values, note that integers are not necessarily
         assigned monotonously increasingly. */
/* *
   * Gsasl_qop:
   * @GSASL_QOP_AUTH: Authentication only.
   * @GSASL_QOP_AUTH_INT: Authentication and integrity.
   * @GSASL_QOP_AUTH_CONF: Authentication, integrity and confidentiality.
   *
   * Quality of Protection types (DIGEST-MD5 and GSSAPI).  The
   * integrity and confidentiality values is about application data
   * wrapping.  We recommend that you use @GSASL_QOP_AUTH with TLS as
   * that combination is generally more secure and have better chance
   * of working than the integrity/confidentiality layers of SASL.
   */
/* *
   * Gsasl_saslprep_flags:
   * @GSASL_ALLOW_UNASSIGNED: Allow unassigned code points.
   *
   * Flags for the SASLprep function, see gsasl_saslprep().  For
   * background, see the GNU Libidn documentation.
   */
/* *
   * Gsasl:
   *
   * Handle to global library context.
   */
/* *
   * Gsasl_session:
   *
   * Handle to SASL session context.
   */
/* *
   * Gsasl_property:
   * @GSASL_AUTHID: Authentication identity (username).
   * @GSASL_AUTHZID: Authorization identity.
   * @GSASL_PASSWORD: Password.
   * @GSASL_ANONYMOUS_TOKEN: Anonymous identifier.
   * @GSASL_SERVICE: Service name
   * @GSASL_HOSTNAME: Host name.
   * @GSASL_GSSAPI_DISPLAY_NAME: GSS-API credential principal name.
   * @GSASL_PASSCODE: SecurID passcode.
   * @GSASL_SUGGESTED_PIN: SecurID suggested PIN.
   * @GSASL_PIN: SecurID PIN.
   * @GSASL_REALM: User realm.
   * @GSASL_DIGEST_MD5_HASHED_PASSWORD: Pre-computed hashed DIGEST-MD5
   *   password, to avoid storing passwords in the clear.
   * @GSASL_QOPS: Set of quality-of-protection values.
   * @GSASL_QOP: Quality-of-protection value.
   * @GSASL_SCRAM_ITER: Number of iterations in password-to-key hashing.
   * @GSASL_SCRAM_SALT: Salt for password-to-key hashing.
   * @GSASL_SCRAM_SALTED_PASSWORD: Hex-encoded hashed/salted password.
   * @GSASL_SCRAM_SERVERKEY: Hex-encoded SCRAM ServerKey derived
   *   from users' passowrd.
   * @GSASL_SCRAM_STOREDKEY: Hex-encoded SCRAM StoredKey derived
   *   from users' passowrd.
   * @GSASL_CB_TLS_UNIQUE: Base64 encoded tls-unique channel binding.
   * @GSASL_SAML20_IDP_IDENTIFIER: SAML20 user IdP URL.
   * @GSASL_SAML20_REDIRECT_URL: SAML 2.0 URL to access in browser.
   * @GSASL_OPENID20_REDIRECT_URL: OpenID 2.0 URL to access in browser.
   * @GSASL_OPENID20_OUTCOME_DATA: OpenID 2.0 authentication outcome data.
   * @GSASL_SAML20_AUTHENTICATE_IN_BROWSER: Request to perform SAML 2.0
   *   authentication in browser.
   * @GSASL_OPENID20_AUTHENTICATE_IN_BROWSER: Request to perform OpenID 2.0
   *   authentication in browser.
   * @GSASL_VALIDATE_SIMPLE: Request for simple validation.
   * @GSASL_VALIDATE_EXTERNAL: Request for validation of EXTERNAL.
   * @GSASL_VALIDATE_ANONYMOUS: Request for validation of ANONYMOUS.
   * @GSASL_VALIDATE_GSSAPI: Request for validation of GSSAPI/GS2.
   * @GSASL_VALIDATE_SECURID: Reqest for validation of SecurID.
   * @GSASL_VALIDATE_SAML20: Reqest for validation of SAML20.
   * @GSASL_VALIDATE_OPENID20: Reqest for validation of OpenID 2.0 login.
   *
   * Callback/property types.
   */
/* Information properties, e.g., username. */
/* Client callbacks. */
/* Server validation callback properties. */
/* *
   * Gsasl_callback_function:
   * @ctx: libgsasl handle.
   * @sctx: session handle, may be NULL.
   * @prop: enumerated value of Gsasl_property type.
   *
   * Prototype of function that the application should implement.  Use
   * gsasl_callback_set() to inform the library about your callback
   * function.
   *
   * It is called by the SASL library when it need some information
   * from the application.  Depending on the value of @prop, it should
   * either set some property (e.g., username or password) using
   * gsasl_property_set(), or it should extract some properties (e.g.,
   * authentication and authorization identities) using
   * gsasl_property_fast() and use them to make a policy decision,
   * perhaps returning GSASL_AUTHENTICATION_ERROR or GSASL_OK
   * depending on whether the policy permitted the operation.
   *
   * Return value: Any valid return code, the interpretation of which
   *   depend on the @prop value.
   *
   * Since: 0.2.0
   **/
/* Library entry and exit points: version.c, init.c, done.c */
/* Callback handling: callback.c */
/* Property handling: property.c */
/* Mechanism handling: listmech.c, supportp.c, suggest.c */
/* Authentication functions: xstart.c, xstep.c, xfinish.c */
/* Session functions: xcode.c, mechname.c */
/* Error handling: error.c */
/* *
 * gsasl_strerror_name:
 * @err: libgsasl error code
 *
 * Convert return code to human readable string representing the error
 * code symbol itself.  For example, gsasl_strerror_name(%GSASL_OK)
 * returns the string "GSASL_OK".
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * This function is one of few in the library that can be used without
 * a successful call to gsasl_init().
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing a string version of the error code @err, or NULL if
 *   the error code is not known.
 *
 * Since: 0.2.29
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_strerror_name(mut err: libc::c_int)
 -> *const libc::c_char {
    if err < 0 as libc::c_int ||
           err >=
               (::std::mem::size_of::<[C2RustUnnamed_0; 69]>() as
                    libc::c_ulong).wrapping_div(::std::mem::size_of::<C2RustUnnamed_0>()
                                                    as libc::c_ulong) as
                   libc::c_int {
        return 0 as *const libc::c_char
    }
    return errors[err as usize].name;
}
