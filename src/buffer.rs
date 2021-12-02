use std::ffi::CStr;
use rsasl_c2rust::free::gsasl_free;

///  A type representing an owned buffer compatible to libgsasl
///
///  For most purposes this acts like a Box<[u8]>.  The main reason for its existance is to prevent
///  allocator corruption or other bad behaviour in the case that libgsasl uses a different
///  allocator to the Rust runtime (e.g. glibc malloc vs jemalloc).  SaslBuffer implements
///  Deref<Target=[u8]> which is where most of the API comes from.
#[derive(Debug)]
pub struct SaslBuffer {
    ptr: *mut u8,
    len: usize,
}

impl SaslBuffer {
    /// Take ownership of a raw pointer + len returned by libgsasl.
    pub fn from_parts(ptr: *mut libc::c_char, len: usize) -> Self {
        let ptr = ptr as *mut u8;
        Self { ptr, len }
    }

    pub fn as_raw_ptr(&self) -> *const libc::c_char {
        self.ptr as *const libc::c_char
    }
}

impl Drop for SaslBuffer {
    fn drop(&mut self) {
        // Free the owned pointer.  This uses `gsasl_free` instead of `libc::free` for the case
        // that libgsasl was linked with a different malloc/free implementation than libc was.
        unsafe { gsasl_free(self.ptr as *mut libc::c_void); }
    }
}

impl std::ops::Deref for SaslBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // Construct a slice from the pointer + len combination.  This is not well defined in the
        // case that the length is greater than the actual data.  Which can safely be considered a
        // bug in libgsasl.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// A type representing an owned string compatible to libgsasl
///
/// This struct is different to `std::ffi::CString` in one important regard: It will always use the
/// `free` function used by libgsasl which will prevent any allocator corruption.
/// It implements `Deref<Target=CStr>` so all functions useable with a &CStr are usable with a
/// &SaslString.
#[derive(Debug)]
pub struct SaslString {
    ptr: *mut libc::c_char,
}

impl SaslString {
    /// Takes ownership of a raw pointer returned by libgsasl.
    pub fn from_raw(ptr: *mut libc::c_char) -> Self {
        Self { ptr }
    }

    pub fn as_raw_ptr(&self) -> *const libc::c_char {
        self.ptr as *const libc::c_char
    }
}

impl Drop for SaslString {
    fn drop(&mut self) {
        // Properly free this string.  This uses `gsasl_free` instead of `libc::free` for the case
        // that libgsasl was linked with a different malloc/free implementation than libc was.
        unsafe { gsasl_free(self.ptr as *mut libc::c_void); }
    }
}

impl std::ops::Deref for SaslString {
    type Target = CStr;

    fn deref(&self) -> &Self::Target {
        // Creating a CStr from a raw pointer is unsafe for several reasons.  We need to make it
        // safe.  Since we own the underlying data the lifetime of this reference will never be
        // less specific than the validity of the underlying pointer.  Mutation is prevented by us
        // only ever retuning non-mutable references.  The fact that the pointer is valid and
        // aligned and that there exist a terminating nul is assumed, either of those not being the
        // case would be a heavy bug in libgsasl.
        unsafe { CStr::from_ptr(self.ptr) }
    }
}
