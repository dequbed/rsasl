use gsasl_sys::*;
use std::ptr;
use std::ffi::CStr;

pub struct SASL {
    ctx: *mut Gsasl,
}

impl SASL {
    /// Creates and initializes a new SASL context.
    pub fn new() -> Result<Self, libc::c_int> {
        let mut s = SASL {
            ctx: ptr::null_mut()
        };

        s.init()?;

        Ok(s)
    }

    /// Initialize a SASL context. Has to be run before most other functions are called
    fn init(&mut self) -> Result<(), libc::c_int> {
        // Initialize the context
        let res = unsafe {
            gsasl_init(self.ctx as *mut *mut Gsasl)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(res)
        } else {
            Ok(())
        }
    }

    pub fn client_start(&mut self, mech: &CStr) -> Result<Session, libc::c_int> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let res = unsafe {
            gsasl_client_start(self.ctx, mech.as_ptr(), &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(res)
        } else {
            let session = Session::from_ptr(ptr);
            Ok(session)
        }
    }

    pub fn server_start(&mut self, mech: &CStr) -> Result<Session, libc::c_int> {
        let mut ptr: *mut Gsasl_session = ptr::null_mut();
        let res = unsafe {
            gsasl_server_start(self.ctx, mech.as_ptr(), &mut ptr as *mut *mut Gsasl_session)
        };

        if res != (Gsasl_rc_GSASL_OK as libc::c_int) {
            Err(res)
        } else {
            let session = Session::from_ptr(ptr);
            Ok(session)
        }
    }
}

impl Drop for SASL {
    fn drop(&mut self) {
        unsafe {
            gsasl_done(self.ctx);
        }
    }
}

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

pub struct SaslBuffer {
    ptr: *mut u8,
    len: usize,
}

impl SaslBuffer {
    pub fn from_parts(ptr: *mut libc::c_char, len: usize) -> Self {
        let ptr = ptr as *mut u8;
        Self { ptr, len }
    }
}

impl Drop for SaslBuffer {
    fn drop(&mut self) {
        unsafe {
            gsasl_free(self.ptr as *mut libc::c_void);
        }
    }
}

impl std::ops::Deref for SaslBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            std::slice::from_raw_parts(self.ptr, self.len)
        }
    }
}
