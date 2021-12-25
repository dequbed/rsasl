use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::ptr::NonNull;
use libc::size_t;
use crate::{GSASL_OK, GSASL_UNKNOWN_MECHANISM, RsaslError, SASL, SaslError, Session};
use crate::consts::GSASL_NEEDS_MORE;
use crate::gsasl::plain::client::Plain;
use crate::session::StepResult;
use crate::Step::{Done, NeedsMore};

#[derive(Clone, Debug)]
pub struct MechContainer<C, S> {
    pub name: &'static str,
    pub client: C,
    pub server: S,
}
impl<C: MechanismBuilder, S: MechanismBuilder> MechContainer<C, S> {
    pub fn init(&mut self) {
        self.client.init();
        self.server.init();
    }
}

pub trait Mech: Debug {
    fn name(&self) -> &'static str;
    fn client(&self) -> &dyn MechanismBuilder;
    fn server(&self) -> &dyn MechanismBuilder;
}

impl<C: MechanismBuilder, S: MechanismBuilder> Mech for MechContainer<C, S> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn client(&self) -> &dyn MechanismBuilder {
        &self.client
    }

    fn server(&self) -> &dyn MechanismBuilder {
        &self.server
    }
}

pub trait OutputError {}
impl OutputError for std::io::Error {}
pub trait OutputWriter {
    type Error: OutputError;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
}
impl<W: Write> OutputWriter for W {
    type Error = std::io::Error;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Write::write(self, buf)
    }
}

pub trait MechanismBuilder: Debug {
    fn init(&self) {}
    fn start(&self, sasl: &SASL) -> Result<Box<dyn Mechanism>, RsaslError>;
}

pub trait Mechanism: Debug {
    // State is four things: currently writing output, has written all output(Done, NeedsMore),
    // Error
    // Surrounding protocol knows the wrapping of SASL => input is always complete!
    fn step(&mut self,
            session: &mut Session,
            input: Option<&[u8]>,
            writer: &mut dyn Write
    ) -> StepResult;
}

pub trait SecurityLayer {
    fn encode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SaslError>;
    fn decode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SaslError>;
}

#[derive(Copy, Clone)]
pub struct Gsasl_mechanism {
    pub name: &'static str,
    pub client: MechanismVTable,
    pub server: MechanismVTable,
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
impl Debug for MechanismVTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MechanismVTable")
            .field("has init", &self.init.is_some())
            .field("has done", &self.done.is_some())
            .field("has start", &self.start.is_some())
            .field("has step", &self.step.is_some())
            .field("has finish", &self.finish.is_some())
            .field("has encode", &self.encode.is_some())
            .field("has decode", &self.decode.is_some())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct CMechBuilder {
    pub vtable: MechanismVTable,
}

impl MechanismBuilder for CMechBuilder {
    fn init(&self) {
        if let Some(init) = self.vtable.init {
            unsafe { init() };
        }
    }

    fn start(&self, sasl: &SASL) -> Result<Box<dyn Mechanism>, RsaslError> {
        if let Some(start) = self.vtable.start {
            let mut mech_data = None;
            let res =  unsafe { start(sasl, &mut mech_data) };
            if res == GSASL_OK as libc::c_int {
                return Ok(Box::new(CMech { vtable: self.vtable, mech_data }));
            } else {
                return Err(res as libc::c_uint);
            }
        } else {
            return Ok(Box::new(CMech { vtable: self.vtable, mech_data: None }));
        }
    }
}

impl Drop for CMechBuilder {
    fn drop(&mut self) {
        if let Some(done) = self.vtable.done {
            unsafe { done() };
        }
    }
}

#[derive(Clone, Debug)]
pub struct CMech {
    vtable: MechanismVTable,
    mech_data: Option<NonNull<()>>,
}

impl Mechanism for CMech {
    fn step(&mut self, session: &mut Session, input: Option<&[u8]>, writer: &mut dyn Write)
        -> StepResult
    {
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
                        writer.write_all(outslice)?;
                        Ok(Done(Some(outlen)))
                    }
                } else if res == GSASL_NEEDS_MORE as libc::c_int {
                    if output.is_null() {
                        Ok(NeedsMore(None))
                    } else {
                        let outslice = std::slice::from_raw_parts_mut(output as *mut u8, outlen);
                        writer.write_all(outslice)?;
                        Ok(NeedsMore(Some(outlen)))
                    }
                } else {
                    Err((res as u32).into())
                }
            }
        } else {
            Err(GSASL_UNKNOWN_MECHANISM.into())
        }
    }
}

impl Drop for CMech {
    fn drop(&mut self) {
        if let Some(finish) = self.vtable.finish {
            unsafe { finish(self.mech_data) };
        }
    }
}

pub type Gsasl_code_function = Option<unsafe fn(
    _: &mut Session,
    _: Option<NonNull<()>>,
    _: *const libc::c_char, _: size_t,
    _: *mut *mut libc::c_char, _: *mut size_t
) -> libc::c_int>;

pub type Gsasl_start_function = Option<unsafe fn(
    _: &SASL,
    _: &mut Option<NonNull<()>>
) -> libc::c_int>;


pub type Gsasl_step_function = Option<unsafe fn(
    _: &mut Session,
    _: Option<NonNull<()>>,
    _: Option<&[u8]>,
    _: *mut *mut libc::c_char, _: *mut size_t
) -> libc::c_int>;

pub type Gsasl_finish_function = Option<unsafe fn(
    _: Option<NonNull<()>>,
) -> ()>;

pub type Gsasl_init_function = Option<unsafe fn() -> libc::c_int>;
pub type Gsasl_done_function = Option<unsafe fn() -> ()>;