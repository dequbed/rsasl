use std::ptr;
use gsasl_sys::*;
use crate::buffer::SaslBuffer;

pub struct Session {
    ptr: *mut Gsasl_session,
}

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

    pub fn step(&mut self, input: &[u8]) -> Result<SaslBuffer, libc::c_int> {

        // rustc can't prove this will never be read so we need to initialize it to a (bogus)
        // value.
        let mut output: *mut libc::c_char = ptr::null_mut();
        let mut output_len: size_t = 0;

        let res;

        unsafe {
            res = gsasl_step(self.ptr, 
                input.as_ptr() as *const libc::c_char, 
                input.len() as size_t, 
                &mut output as *mut *mut libc::c_char, 
                &mut output_len as *mut size_t
            );
        }

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(res)
        } else {
            Ok(SaslBuffer::from_parts(output, output_len as usize))
        }

    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            gsasl_finish(self.ptr);
        }
    }
}
