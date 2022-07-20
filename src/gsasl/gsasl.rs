use crate::error::{Gsasl, SASLError};
use crate::error::SessionError;
use crate::gsasl::consts::{GSASL_NEEDS_MORE, GSASL_OK, GSASL_UNKNOWN_MECHANISM};
use crate::mechanism::Authentication;
use crate::session::{MechanismData, State, StepResult};
use libc::{c_char, size_t};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::ptr::NonNull;
use crate::Shared;

#[derive(Copy, Clone)]
pub struct Gsasl_mechanism {
    pub name: &'static str,
    pub(crate) client: MechanismVTable,
    pub(crate) server: MechanismVTable,
}

#[derive(Copy, Clone)]
pub(crate) struct MechanismVTable {
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
/// Mechanism state keeper for the mechanisms still implemented in C
///
/// This needs to keep hold of the mechanism data and the mechanism vtable
pub(crate) struct CMechanismStateKeeper {
    mech_data: Option<NonNull<()>>,
    vtable: MechanismVTable,
}

impl CMechanismStateKeeper {
    pub fn build(vtable: MechanismVTable) -> Result<Box<dyn Authentication>, SASLError> {
        if vtable.init.is_some() {
            panic!("Initialization of C Mechanism at a global level is not implemented")
        }

        let mut mech_data = None;

        if let Some(start) = vtable.start {
            let rc = unsafe { start(&Shared, &mut mech_data) };
            if rc != GSASL_OK as i32 {
                return Err(SASLError::Gsasl(Gsasl(rc as libc::c_uint)));
            }
        }

        Ok(Box::new(CMechanismStateKeeper { mech_data, vtable }))
    }
}

impl Authentication for CMechanismStateKeeper {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        fn write_output(
            writer: &mut dyn Write,
            output: *mut c_char,
            outlen: size_t,
        ) -> Result<Option<usize>, SessionError> {
            // Output == nullptr means send no data
            if output.is_null() {
                Ok(None)
            } else {
                // Output != nullptr but outlen == 0 means send data of zero len
                if outlen > 0 {
                    let outslice = unsafe {
                        std::slice::from_raw_parts(output as *const _ as *const u8, outlen)
                    };
                    writer.write_all(outslice)?;
                }
                Ok(Some(outlen))
            }
        }

        if let Some(step) = self.vtable.step {
            // The Output is allocated by the C mechanisms and needs to be freed by us
            let mut output: *mut c_char = std::ptr::null_mut();
            let mut outlen: size_t = 0;

            unsafe {
                let res = step(
                    session,
                    self.mech_data.clone(),
                    input,
                    &mut output,
                    &mut outlen,
                );
                if res == GSASL_OK as libc::c_int {
                    Ok((State::Finished, write_output(writer, output, outlen)?))
                } else if res == GSASL_NEEDS_MORE as libc::c_int {
                    Ok((State::Running, write_output(writer, output, outlen)?))
                } else {
                    Err(Gsasl(res as libc::c_uint).into())
                }
            }
        } else {
            Err(Gsasl(GSASL_UNKNOWN_MECHANISM as libc::c_uint).into())
        }
    }
}

impl Drop for CMechanismStateKeeper {
    fn drop(&mut self) {
        if let Some(finish) = self.vtable.finish {
            unsafe { finish(self.mech_data) };
        }
    }
}

pub(crate) type Gsasl_code_function = Option<
    unsafe fn(
        _: &mut MechanismData,
        _: Option<NonNull<()>>,
        _: *const libc::c_char,
        _: size_t,
        _: *mut *mut libc::c_char,
        _: *mut size_t,
    ) -> libc::c_int,
>;

pub(crate) type Gsasl_start_function =
    Option<unsafe fn(_: &Shared, _: &mut Option<NonNull<()>>) -> libc::c_int>;

pub(crate) type Gsasl_step_function = Option<
    unsafe fn(
        _: &mut MechanismData,
        _: Option<NonNull<()>>,
        _: Option<&[u8]>,
        _: *mut *mut libc::c_char,
        _: *mut size_t,
    ) -> libc::c_int,
>;

pub(crate) type Gsasl_finish_function = Option<unsafe fn(_: Option<NonNull<()>>) -> ()>;

pub(crate) type Gsasl_init_function = Option<unsafe fn() -> libc::c_int>;
pub(crate) type Gsasl_done_function = Option<unsafe fn() -> ()>;
