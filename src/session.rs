use std::ptr;
use std::ffi::CStr;
use gsasl_sys::*;
use gsasl_sys::Gsasl_rc::*;

use crate::buffer::{SaslBuffer, SaslString};
use crate::error::{Result, SaslError};

#[derive(Debug)]
pub struct Session<D> {
    ptr: *mut Gsasl_session,
    phantom: std::marker::PhantomData<D>,
}

#[derive(Debug)]
pub enum Step<T> {
    Done(T),
    NeedsMore(T),
}

pub type StepResult<T> = Result<Step<T>>;

impl<D> Session<D> {
    pub fn from_ptr(ptr: *mut Gsasl_session) -> Self {
        let phantom = std::marker::PhantomData;
        Self { ptr, phantom }
    }

    pub fn set_property(&mut self, prop: Gsasl_property, data: &[u8]) {
        let data_ptr = data.as_ptr() as *const libc::c_char;
        let len = data.len() as size_t;
        unsafe {
            gsasl_property_set_raw(self.ptr, prop, data_ptr, len);
        }
    }

    pub fn get_property_fast(&self, prop: Gsasl_property) -> &CStr {
        unsafe { 
            let ptr = gsasl_property_fast(self.ptr, prop) ;
            CStr::from_ptr(ptr)
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

    /// Store some data in the Session context
    ///
    /// This allows a callback to later access that data using `retrieve` or `retrieve_mut`
    pub fn store(&mut self, data: Box<D>) {
        unsafe {
            gsasl_session_hook_set(self.ptr, Box::into_raw(data) as *mut libc::c_void);
        }
    }

    /// Retrieve the data stored with `store`, leaving nothing in its place
    ///
    /// This function will return `None` if no data was stored. This function is unsafe because we
    /// can not guarantee that there is currently nothing else that has a reference to the data
    /// which will turn into a dangling pointer if the returned Box is dropped
    pub unsafe fn retrieve(&mut self) -> Option<Box<D>> {
        // This function is unsa
        // Get a pointer to the current value
        let ptr = gsasl_session_hook_get(self.ptr);
        // Set it to null because we now have sole ownership
        gsasl_session_hook_set(self.ptr, std::ptr::null_mut());

        if !ptr.is_null() {
            Some(Box::from_raw(ptr as *mut D))
        } else {
            None
        }
    }

    /// Retrieve a mutable reference to the data stored with `store`
    ///
    /// This is an alternative to `retrieve_raw` that does not take ownership of the stored data,
    /// thus also not dropping it after it has left the current scope. Mainly useful for callbacks
    ///
    /// The function tries to return `None` if no data was stored.
    pub fn retrieve_mut(&mut self) -> Option<&mut D> {
        // This is safe because once you have given ownership of data to the context you can only
        // get it back using `unsafe` functions.
        unsafe {
            let ptr = gsasl_session_hook_get(self.ptr) as *mut D;
            ptr.as_mut()
        }
    }

    pub fn finish(&mut self) {
        unsafe { gsasl_finish(self.ptr) };
    }
}
