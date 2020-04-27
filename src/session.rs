use std::ptr;
use std::ffi::CStr;
use gsasl_sys::*;
use gsasl_sys::Gsasl_rc::*;

use crate::buffer::{SaslBuffer, SaslString};
use crate::error::{Result, SaslError};

#[derive(Debug)]
pub struct Session {
    ptr: *mut Gsasl_session,
}

#[derive(Debug)]
pub enum Step<T> {
    Done(T),
    NeedsMore(T),
}

pub type StepResult<T> = Result<Step<T>>;

impl Session {
    pub fn from_ptr(ptr: *mut Gsasl_session) -> Self {
        Self { ptr }
    }

    pub fn set_property(&mut self, prop: Gsasl_property, data: &[u8]) {
        let data_ptr = data.as_ptr() as *const libc::c_char;
        let len = data.len() as size_t;
        unsafe {
            gsasl_property_set_raw(self.ptr, prop, data_ptr, len);
        }
    }

    /// Perform one step of SASL authentication. This reads data from `input`, processes it
    /// (potentially calling the configured callback) and returns data to be returned to the other
    /// end.
    ///
    /// Note: This function may leak memory on failure.
    pub fn step(&mut self, input: &[u8]) -> StepResult<SaslBuffer> {
        // rustc can't prove this will never be read so we need to initialize it to a (bogus)
        // value.
        let mut output: *mut libc::c_char = ptr::null_mut();
        let mut output_len: size_t = 0;

        let res = unsafe {
            gsasl_step(self.ptr,
                input.as_ptr() as *const libc::c_char,
                input.len() as size_t,
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
            Err(SaslError(res))
        }
    }

    /// A simple wrapper around the interal step function that base64-decodes the input and
    /// base64-encodes the output. Mainly useful for text-based protocols.
    ///
    /// Note: This function may leak memory on failure since the interal step function does as well.
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
            Err(SaslError(res))
        }
    }

    pub fn finish(&mut self) {
        unsafe { gsasl_finish(self.ptr) };
    }
}
