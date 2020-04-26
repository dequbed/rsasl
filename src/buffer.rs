use gsasl_sys::*;

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
