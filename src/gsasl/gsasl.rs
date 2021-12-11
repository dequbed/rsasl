use std::ptr::NonNull;
use libc::size_t;
use crate::consts::RsaslError;
use crate::gsasl::consts::Gsasl_property;
use crate::{gsasl_done, GSASL_OK};
use crate::gsasl::init::register_builtin_mechs;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Gsasl {
    pub n_client_mechs: size_t,
    pub client_mechs: *mut Gsasl_mechanism,
    pub n_server_mechs: size_t,
    pub server_mechs: *mut Gsasl_mechanism,
    pub cb: Gsasl_callback_function,
    pub application_hook: *mut libc::c_void,
}

impl Gsasl {
    pub fn new() -> Result<Self, RsaslError> {
        unsafe {
            let mut this = Self {
                n_client_mechs: 0,
                client_mechs: std::ptr::null_mut(),
                n_server_mechs: 0,
                server_mechs: std::ptr::null_mut(),
                cb: None,
                application_hook: std::ptr::null_mut(),
            };

            let mut rc: libc::c_int = 0;
            rc = register_builtin_mechs(&mut this);

            if rc != GSASL_OK as libc::c_int {
                gsasl_done(&mut this);
                return Err(rc as RsaslError);
            }

            Ok(this)
        }
    }
}

pub type Gsasl_callback_function = Option<
    unsafe fn(_: *mut Gsasl, _: *mut Gsasl_session, _: Gsasl_property) -> libc::c_int
>;

/* Per-session library handle. */
#[derive(Copy, Clone)]
pub struct Gsasl_session {
    pub ctx: *mut Gsasl,
    pub clientp: libc::c_int,
    pub mech: *mut Gsasl_mechanism,
    pub mech_data: Option<NonNull<()>>,
    pub application_hook: *mut libc::c_void,
    pub anonymous_token: *mut libc::c_char,
    pub authid: *mut libc::c_char,
    pub authzid: *mut libc::c_char,
    pub password: *mut libc::c_char,
    pub passcode: *mut libc::c_char,
    pub pin: *mut libc::c_char,
    pub suggestedpin: *mut libc::c_char,
    pub service: *mut libc::c_char,
    pub hostname: *mut libc::c_char,
    pub gssapi_display_name: *mut libc::c_char,
    pub realm: *mut libc::c_char,
    pub digest_md5_hashed_password: *mut libc::c_char,
    pub qops: *mut libc::c_char,
    pub qop: *mut libc::c_char,
    pub scram_iter: *mut libc::c_char,
    pub scram_salt: *mut libc::c_char,
    pub scram_salted_password: *mut libc::c_char,
    pub scram_serverkey: *mut libc::c_char,
    pub scram_storedkey: *mut libc::c_char,
    pub cb_tls_unique: *mut libc::c_char,
    pub saml20_idp_identifier: *mut libc::c_char,
    pub saml20_redirect_url: *mut libc::c_char,
    pub openid20_redirect_url: *mut libc::c_char,
    pub openid20_outcome_data: *mut libc::c_char,
}

#[derive(Copy, Clone)]
pub struct Gsasl_mechanism {
    pub name: &'static str,
    pub client: Gsasl_mechanism_functions,
    pub server: Gsasl_mechanism_functions,
}

#[derive(Copy, Clone)]
pub struct Gsasl_mechanism_functions {
    pub init: Gsasl_init_function,
    pub done: Gsasl_done_function,
    pub start: Gsasl_start_function,
    pub step: Gsasl_step_function,
    pub finish: Gsasl_finish_function,
    pub encode: Gsasl_code_function,
    pub decode: Gsasl_code_function,
}


pub type Gsasl_code_function = Option<unsafe fn(
    _: *mut Gsasl_session,
    _: Option<NonNull<()>>,
    _: *const libc::c_char, _: size_t,
    _: *mut *mut libc::c_char, _: *mut size_t
) -> libc::c_int>;

pub type Gsasl_finish_function = Option<unsafe fn(
    _: *mut Gsasl_session,
    _: Option<NonNull<()>>,
) -> ()>;

/*
pub unsafe fn step(
    mut sctx: *mut Gsasl_session,
    mut _mech_data: *mut libc::c_void,
    mut _input: *const libc::c_char,
    mut _input_len: size_t,
    mut output: *mut *mut libc::c_char,
    mut output_len: *mut size_t);
 */

pub enum Step {
    Done(Option<Box<[u8]>>),
    NeedsMore(Option<Box<[u8]>>),
}
pub type StepResult = Result<Step, RsaslError>;

pub type Gsasl_step_function = Option<unsafe fn(
    _: *mut Gsasl_session,
    _: Option<NonNull<()>>,
    _: Option<&[u8]>,
    _: *mut *mut libc::c_char, _: *mut size_t
) -> libc::c_int>;

pub type Gsasl_start_function = Option<unsafe fn(
    _: &mut Gsasl_session,
    _: &mut Option<NonNull<()>>
) -> libc::c_int>;

pub type Gsasl_done_function = Option<unsafe fn(_: &mut Gsasl) -> ()>;

pub type Gsasl_init_function = Option<unsafe fn(_: &mut Gsasl) -> libc::c_int>;
