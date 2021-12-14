use libc::size_t;
use std::ptr;
use std::ffi::CStr;
use crate::gsasl::consts::GSASL_OK;

use crate::buffer::{SaslBuffer, SaslString};
use crate::error::{Result, SaslError};

use discard::{Discard};
use crate::gsasl::consts::{GSASL_NEEDS_MORE, Gsasl_property};
use crate::gsasl::gsasl::Gsasl_session;
use crate::gsasl::property::{gsasl_property_fast, gsasl_property_set_raw};
use crate::gsasl::xfinish::gsasl_finish;
use crate::gsasl::xstep::{gsasl_step, gsasl_step64};
use crate::Property;

#[derive(Debug)]
/// The context of an authentication exchange
///
/// This struct will call the necesarry initializers on construction and finalizers when
/// `discarded`. If manual housekeeping is required the session can be leaked with
/// [`DiscardOnDrop::leak`](discard::DiscardOnDrop::leak).
pub struct Session<D> {
    ptr: *mut Gsasl_session,
    phantom: std::marker::PhantomData<D>,
}

#[derive(Debug)]
/// The outcome of a single step in the authentication exchange
///
/// Since SASL is multi-step each step can either complete the exchange or require more steps to be
/// performed. In both cases however it may provide data that has to be forwarded to the other end.
pub enum Step<T> {
    Done(T),
    NeedsMore(T),
}

pub type StepResult<T> = Result<Step<T>>;

impl<D> Session<D> {
    /// Perform one step of SASL authentication. This reads data from `input` then processes it,
    /// potentially calling a configured callback for required properties or enact decisions, and
    /// finally returns data to be send to the other party.
    ///
    /// Note: This function may leak memory on internal failure.
    pub fn step(&mut self, input: &[u8]) -> StepResult<SaslBuffer> {
        // rustc can't prove this will never be read so we need to initialize it to a (bogus)
        // value.
        let mut output: *mut libc::c_char = ptr::null_mut();
        let mut output_len: size_t = 0;

        let res = unsafe {
            gsasl_step(self.ptr,
                Some(input),
                &mut output as *mut *mut libc::c_char,
                &mut output_len as *mut size_t
            )
        };

        // Should the gsasl_step function fail (i.e. return something that's not GSASL_OK or
        // GSASL_NEEDS_MORE) the value and contents of `output` are unspecified. Thus we can't wrap
        // it in a SaslBuffer since that would potentially double free. XXX: This may leak memory

        if res == (GSASL_OK as libc::c_int) {
            Ok(Step::Done(SaslBuffer::from_parts(output, output_len as usize)))
        } else if res == (GSASL_NEEDS_MORE as libc::c_int) {
            Ok(Step::NeedsMore(SaslBuffer::from_parts(output, output_len as usize)))
        } else {
            Err(SaslError(res as u32))
        }
    }

    /// A simple wrapper around the gsasl step function that base64-decodes the input and
    /// base64-encodes the output. Mainly useful for text-based protocols.
    ///
    /// Note: This function may leak memory on failure since the internal step function does as well.
    pub fn step64(&mut self, input: &CStr) -> StepResult<SaslString> {
        let mut output: *mut libc::c_char = ptr::null_mut();

        let res = unsafe {
            gsasl_step64(self.ptr, input.as_ptr(), &mut output as *mut *mut libc::c_char)
        };

        if res == (GSASL_OK as libc::c_int) {
            Ok(Step::Done(SaslString::from_raw(output)))
        } else if res == (GSASL_NEEDS_MORE as libc::c_int) {
            Ok(Step::NeedsMore(SaslString::from_raw(output)))
        } else {
            Err(SaslError(res as u32))
        }
    }

    /// Set a property in the session context
    ///
    /// A `property` in this context is a piece of information used by authentication mechanisms,
    /// for example the Authcid, Authzid and Password for PLAIN.
    /// This is the Rust equivalent to the `gsasl_property_set` funciton.
    pub fn set_property(&mut self, prop: Property, data: &[u8]) {
        let data_ptr = data.as_ptr() as *const libc::c_char;
        let len = data.len() as size_t;
        unsafe {
            gsasl_property_set_raw(self.ptr, prop, data_ptr, len);
        }
    }

    /// Try to read a property from the session context
    ///
    /// This maps to `gsasl_property_fast` meaning it will *not* call the callback to retrieve
    /// properties it does not know about.
    ///
    /// Returns `None` if the property is now known or was not set
    pub fn get_property(&self, prop: Property) -> Option<&CStr> {
        unsafe { 
            let ptr = gsasl_property_fast(self.ptr, prop as Gsasl_property);
            if !ptr.is_null() {
                Some(CStr::from_ptr(ptr))
            } else {
                None
            }
        }
    }

    pub(crate) fn from_ptr(ptr: *mut Gsasl_session) -> Self {
        let phantom = std::marker::PhantomData;
        Self { ptr, phantom }
    }

    pub(crate) fn as_ptr(&self) -> *mut Gsasl_session {
        self.ptr
    }

    pub(crate) fn finish(&mut self) {
        unsafe { gsasl_finish(&mut *self.ptr) };
    }
}

impl<D> Discard for Session<D> {
    fn discard(mut self) {
        // Retrieve and drop the stored value. This should always be safe because a session can
        // only be duplicated by running a callback via an exchange or calling `callback`, in which
        // case calling discard will be prevented by the borrow checker.
        self.finish();
    }
}
