use ::libc;
use libc::size_t;
use crate::gsasl::gc::GC_OK;
use crate::gsasl::gl::gc_gnulib::gc_nonce;

extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> size_t;
    fn __assert_fail(__assertion: *const libc::c_char,
                     __file: *const libc::c_char, __line: libc::c_uint,
                     __function: *const libc::c_char) -> !;
}
/* Store zero terminated CRAM-MD5 challenge in output buffer.  The
   CHALLENGE buffer must be allocated by the caller, and must have
   room for CRAM_MD5_CHALLENGE_LEN characters.  Returns 0 on success,
   and -1 on randomness problems.  */
#[no_mangle]
pub unsafe fn cram_md5_challenge(mut challenge: *mut libc::c_char)
 -> libc::c_int {
    let mut nonce: [libc::c_char; 10] = [0; 10];
    let mut i: size_t = 0;
    let mut rc: libc::c_int = 0;
    if strlen(b"<XXXXXXXXXXXXXXXXXXXX.0@localhost>\x00" as *const u8 as
                  *const libc::c_char) == (35 - 1) {
    } else {
        __assert_fail(b"strlen (TEMPLATE) == CRAM_MD5_CHALLENGE_LEN - 1\x00"
                          as *const u8 as *const libc::c_char,
                      b"challenge.c\x00" as *const u8 as *const libc::c_char,
                      74 as libc::c_int as libc::c_uint,
                      (*::std::mem::transmute::<&[u8; 31],
                                                &[libc::c_char; 31]>(b"int cram_md5_challenge(char *)\x00")).as_ptr());
    }
    memcpy(challenge as *mut libc::c_void,
           b"<XXXXXXXXXXXXXXXXXXXX.0@localhost>\x00" as *const u8 as
               *const libc::c_char as *const libc::c_void,
           35);
    rc =
        gc_nonce(nonce.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 10]>())
            as libc::c_int;
    if rc != GC_OK as libc::c_int { return -(1 as libc::c_int) }
    i = 0 as libc::c_int as size_t;
    while i < ::std::mem::size_of::<[libc::c_char; 10]>() {
        *challenge.offset((1 as libc::c_int as libc::c_ulong).wrapping_add(i as u64)
                              as isize) =
            if nonce[i as usize] as libc::c_int & 0xf as libc::c_int >
                   9 as libc::c_int {
                ('0' as i32 +
                     (nonce[i as usize] as libc::c_int & 0xf as libc::c_int))
                    - 10 as libc::c_int
            } else {
                ('0' as i32) +
                    (nonce[i as usize] as libc::c_int & 0xf as libc::c_int)
            } as libc::c_char;
        *challenge.offset((11 as libc::c_int as libc::c_ulong).wrapping_add(i as u64)
                              as isize) =
            if nonce[i as usize] as libc::c_int >> 4 as libc::c_int &
                   0xf as libc::c_int > 9 as libc::c_int {
                ('0' as i32 +
                     (nonce[i as usize] as libc::c_int >> 4 as libc::c_int &
                          0xf as libc::c_int)) - 10 as libc::c_int
            } else {
                ('0' as i32) +
                    (nonce[i as usize] as libc::c_int >> 4 as libc::c_int &
                         0xf as libc::c_int)
            } as libc::c_char;
        i = i.wrapping_add(1)
    }
    return 0 as libc::c_int;
}
