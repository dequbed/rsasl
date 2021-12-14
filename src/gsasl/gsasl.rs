use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ptr::NonNull;
use libc::{c_char, size_t};
use crate::consts::{GSASL_NEEDS_MORE, Property, RsaslError};
use crate::gsasl::consts::Gsasl_property;
use crate::{gsasl_done, GSASL_OK, GSASL_UNKNOWN_MECHANISM, SaslError};
use crate::gsasl::gsasl::Step::{Done, NeedsMore};
use crate::gsasl::init::register_builtin_mechs;

#[derive(Clone)]
#[repr(C)]
pub struct Gsasl {
    /*pub n_client_mechs: size_t,
    pub client_mechs: *mut Gsasl_mechanism,*/
    pub mechs: Vec<CombinedCMech>,
    pub cb: Gsasl_callback_function,
}

impl Gsasl {
    pub fn register(&mut self, name: &'static str, client: MechanismVTable, server: MechanismVTable) {
        let mut mech = CombinedCMech {
            name,
            client: CMechBuilder { vtable: client },
            server: CMechBuilder { vtable: server }
        };
        mech.init(self);
        self.mechs.push(mech);
    }

    pub fn client_start<E>(&self, name: &'static str) -> Result<Gsasl_session, RsaslError> {
        unimplemented!()
    }

    pub fn new() -> Result<Self, RsaslError> {
        unsafe {
            let mut this = Self {
                mechs: Vec::new(),
                cb: None,
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

/*
pub struct Session<'session, E> {
}
 */


/* Per-session library handle. */
pub struct Gsasl_session {
    sasl: &'static Gsasl,
    mechanism: Box<dyn Mechanism>,
    session_data: Option<()>,
    map: HashMap<TypeId, Box<dyn Any>>,

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

impl Gsasl_session {
    pub fn get<P: Property>(&self) -> Option<&P::Item> {
        self.map.get(&TypeId::of::<P::Item>()).and_then(|prop| {
            prop.downcast_ref::<P::Item>()
        })
    }

    pub fn insert<P: Property>(&mut self, item: Box<P::Item>) -> Option<Box<dyn Any>>{
        self.map.insert(TypeId::of::<P::Item>(), item)
    }
}


#[derive(Copy, Clone)]
pub struct Gsasl_mechanism {
    pub name: &'static str,
    pub client: MechanismVTable,
    pub server: MechanismVTable,
}

#[derive(Copy, Clone)]
pub struct CombinedCMech {
    pub name: &'static str,
    pub client: CMechBuilder,
    pub server: CMechBuilder,
}
impl CombinedCMech {
    pub fn init(&mut self, sasl: &mut Gsasl) {
        self.client.init(sasl);
        self.server.init(sasl);
    }
}

#[derive(Copy, Clone)]
pub struct MechanismVTable {
    /// Globally initialize this mechanism. This will be called exactly once per initialization
    /// of Gsasl, however this may be more than once per application. Use [`Once`](std::sync::Once)
    /// and friends if you must only be called once per process space / application
    pub init: Gsasl_init_function,

    /// Undo whatever `init` did. Should be `Drop` in Rust.
    ///
    /// This will usually be called once for every time `init` was called, however in case a
    /// panic occurred it may be called fewer times. If you must ensure that a destructor is run
    /// with higher guarantees, consider the `ctor` crate.
    pub done: Gsasl_done_function,

    /// Start a new authentication using this mechanism
    ///
    /// This function will be called at most once per session. You can rely on the state returned
    /// being used only with the given session with no other authentication exchange happening in
    /// between, i.e. the next function called with it will be either `step` or your Drop
    /// implementation.
    pub start: Gsasl_start_function,

    /// Do a single step of the authentication exchange
    ///
    /// This function will be called after `start` with any data the other party provided. You
    /// can rely on this function not being called again after you returned `Ok(Done)`.
    pub step: Gsasl_step_function,

    /// Should be Drop in Rust
    pub finish: Gsasl_finish_function,


    /// Security layer stuff
    pub encode: Gsasl_code_function,
    pub decode: Gsasl_code_function,
}

pub trait MechanismBuilder {
    fn init(&self, sasl: &mut Gsasl);
    fn start(&self, sasl: &Gsasl, session: &mut Gsasl_session) -> Option<Box<dyn Mechanism>>;
}

pub trait Mechanism {
    fn step(&mut self, session: &mut Gsasl_session, input: Option<&[u8]>) -> StepResult;
    fn encode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SaslError>;
    fn decode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SaslError>;
}

#[derive(Copy, Clone)]
pub struct CMechBuilder {
    pub vtable: MechanismVTable,
}

impl MechanismBuilder for CMechBuilder {
    fn init(&self, sasl: &mut Gsasl) {
        if let Some(init) = self.vtable.init {
            unsafe { init(sasl) };
        }
    }

    fn start(&self, sasl: &Gsasl, session: &mut Gsasl_session) -> Option<Box<dyn Mechanism>> {
        if let Some(start) = self.vtable.start {
            let mut mech_data = None;
            let res =  unsafe { start(session, &mut mech_data) };
            if res == GSASL_OK as libc::c_int {
                return Some(Box::new(CMech { vtable: self.vtable, mech_data }));
            }
        }

        None
    }
}

pub struct CMech {
    vtable: MechanismVTable,
    mech_data: Option<NonNull<()>>,
}

impl Mechanism for CMech {
    fn step(&mut self, session: &mut Gsasl_session, input: Option<&[u8]>) -> StepResult {
        if let Some(step) = self.vtable.step {
            let mut output: *mut libc::c_char = std::ptr::null_mut();
            let mut outlen: size_t = 0;

            unsafe {
                let res = step(session, self.mech_data.clone(), input, &mut output, &mut outlen);
                if res == GSASL_OK as libc::c_int {
                    if output.is_null() {
                        Ok(Done(None))
                    } else {
                        let outslice = std::slice::from_raw_parts_mut(output as *mut u8, outlen);
                        let out = Box::from_raw(outslice);
                        Ok(Done(Some(out)))
                    }
                } else if res == GSASL_NEEDS_MORE as libc::c_int {
                    if output.is_null() {
                        Ok(NeedsMore(None))
                    } else {
                        let outslice = std::slice::from_raw_parts_mut(output as *mut u8, outlen);
                        let out = Box::from_raw(outslice);
                        Ok(NeedsMore(Some(out)))
                    }
                } else {
                    Err(res as libc::c_uint)
                }
            }
        } else {
            Err(GSASL_UNKNOWN_MECHANISM)
        }
    }

    fn encode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SaslError> {
        todo!()
    }

    fn decode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SaslError> {
        todo!()
    }
}


pub type Gsasl_code_function = Option<unsafe fn(
    _: *mut Gsasl_session,
    _: Option<NonNull<()>>,
    _: *const libc::c_char, _: size_t,
    _: *mut *mut libc::c_char, _: *mut size_t
) -> libc::c_int>;

pub type Gsasl_start_function = Option<unsafe fn(
    _: &mut Gsasl_session,
    _: &mut Option<NonNull<()>>
) -> libc::c_int>;

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

pub type Gsasl_finish_function = Option<unsafe fn(
    _: &mut Gsasl_session,
    _: Option<NonNull<()>>,
) -> ()>;

pub type Gsasl_init_function = Option<unsafe fn(_: &mut Gsasl) -> libc::c_int>;
pub type Gsasl_done_function = Option<unsafe fn(_: &mut Gsasl) -> ()>;