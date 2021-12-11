extern "C" {
    fn strverscmp(__s1: *const libc::c_char, __s2: *const libc::c_char)
     -> libc::c_int;
}

/* *
 * gsasl_check_version:
 * @req_version: version string to compare with, or NULL.
 *
 * Check GNU SASL Library version.
 *
 * See %GSASL_VERSION for a suitable @req_version string.
 *
 * This function is one of few in the library that can be used without
 * a successful call to gsasl_init().
 *
 * Return value: Check that the version of the library is at
 *   minimum the one given as a string in @req_version and return the
 *   actual version string of the library; return NULL if the
 *   condition is not met.  If NULL is passed to this function no
 *   check is done and only the version string is returned.
 **/
#[no_mangle]
pub unsafe fn gsasl_check_version(mut req_version:
                                                 *const libc::c_char)
 -> *const libc::c_char {
    if req_version.is_null() ||
           strverscmp(req_version,
                      b"1.11.1.8-d7673\x00" as *const u8 as
                          *const libc::c_char) <= 0 as libc::c_int {
        return b"1.11.1.8-d7673\x00" as *const u8 as *const libc::c_char
    }
    return 0 as *const libc::c_char;
}
