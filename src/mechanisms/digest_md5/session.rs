use ::libc;
use libc::size_t;
use crate::mechanisms::digest_md5::qop::{digest_md5_qop, DIGEST_MD5_QOP_AUTH_CONF,
                                  DIGEST_MD5_QOP_AUTH_INT};
use crate::gsasl::gl::gc_gnulib::gc_hmac_md5;

extern "C" {
    fn rpl_free(ptr: *mut libc::c_void);

    fn malloc(_: size_t) -> *mut libc::c_void;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;

    fn memcmp(_: *const libc::c_void, _: *const libc::c_void,
              _: size_t) -> libc::c_int;
}

pub unsafe fn digest_md5_encode(mut input: *const libc::c_char,
                                           mut input_len: size_t,
                                           mut output: *mut *mut libc::c_char,
                                           mut output_len: *mut size_t,
                                           mut qop: digest_md5_qop,
                                           mut sendseqnum: size_t,
                                           mut key: *mut libc::c_char)
 -> libc::c_int {
    let mut res: libc::c_int = 0;
    if qop as libc::c_uint &
           DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0 {
        return -(1 as libc::c_int)
    } else {
        if qop as libc::c_uint &
               DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0 {
            let mut seqnumin: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut hash: [libc::c_char; 16] = [0; 16];
            let mut len: size_t = 0;
            seqnumin = malloc(input_len.wrapping_add(4)) as *mut libc::c_char;
            if seqnumin.is_null() { return -(1 as libc::c_int) }
            *seqnumin.offset(0 as libc::c_int as isize) =
                (sendseqnum >> 24 & 0xff) as libc::c_char;
            *seqnumin.offset(1 as libc::c_int as isize) =
                (sendseqnum >> 16 & 0xff) as libc::c_char;
            *seqnumin.offset(2 as libc::c_int as isize) =
                (sendseqnum >> 8 & 0xff) as libc::c_char;
            *seqnumin.offset(3 as libc::c_int as isize) =
                (sendseqnum & 0xff) as libc::c_char;
            memcpy(seqnumin.offset(4) as *mut libc::c_void,
                   input as *const libc::c_void,
                   input_len);
            res =
                gc_hmac_md5(key as *const libc::c_void,
                            16 as libc::c_int as size_t,
                            seqnumin as *const libc::c_void,
                            input_len.wrapping_add(4),
                            hash.as_mut_ptr()) as libc::c_int;
            rpl_free(seqnumin as *mut libc::c_void);
            if res != 0 { return -(1 as libc::c_int) }
            *output_len = input_len.wrapping_add(4)
                                   .wrapping_add(10)
                                   .wrapping_add(2)
                                   .wrapping_add(4);

            *output = malloc(*output_len) as *mut libc::c_char;
            if (*output).is_null() { return -(1 as libc::c_int) }
            len = 4 as libc::c_int as size_t;
            memcpy((*output).offset(len as isize) as *mut libc::c_void,
                   input as *const libc::c_void, input_len);
            len = len.wrapping_add(input_len);
            memcpy((*output).offset(len as isize) as *mut libc::c_void,
                   hash.as_mut_ptr() as *const libc::c_void,
                   10);
            len =
                (len as
                     libc::c_ulong).wrapping_add(10 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t;
            memcpy((*output).offset(len as isize) as *mut libc::c_void,
                   b"\x00\x01\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                   2);
            len =
                (len as
                     libc::c_ulong).wrapping_add(2 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t;
            *(*output).offset(len as isize).offset(0 as libc::c_int as isize)
                = (sendseqnum >> 24 & 0xff) as libc::c_char;
            *(*output).offset(len as isize).offset(1 as libc::c_int as isize)
                =
                (sendseqnum >> 16 & 0xff) as libc::c_char;
            *(*output).offset(len as isize).offset(2 as libc::c_int as isize)
                = (sendseqnum >> 8 & 0xff) as libc::c_char;
            *(*output).offset(len as isize).offset(3 as libc::c_int as isize)
                = (sendseqnum & 0xff) as libc::c_char;
            len = len.wrapping_add(4);
            *(*output).offset(0)
                = (len.wrapping_sub(4) >> 24 & 0xff) as libc::c_char;
            *(*output).offset(1 as libc::c_int as isize)
                = (len.wrapping_sub(4) >> 16 & 0xff) as libc::c_char;
            *(*output).offset(2 as libc::c_int as isize)
                = (len.wrapping_sub(4) >> 8 & 0xff) as libc::c_char;
            *(*output).offset(3 as libc::c_int as isize)
                = (len.wrapping_sub(4) & 0xff) as libc::c_char
        } else {
            *output_len = input_len;
            *output = malloc(input_len) as *mut libc::c_char;
            if (*output).is_null() { return -(1 as libc::c_int) }
            memcpy(*output as *mut libc::c_void, input as *const libc::c_void,
                   input_len);
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe fn digest_md5_decode(mut input: *const libc::c_char,
                                           mut input_len: size_t,
                                           mut output: *mut *mut libc::c_char,
                                           mut output_len: *mut size_t,
                                           mut qop: digest_md5_qop,
                                           mut readseqnum: size_t,
                                           mut key: *mut libc::c_char)
 -> libc::c_int {
    if qop as libc::c_uint &
           DIGEST_MD5_QOP_AUTH_CONF as libc::c_int as libc::c_uint != 0 {
        return -(1 as libc::c_int)
    } else {
        if qop as libc::c_uint &
               DIGEST_MD5_QOP_AUTH_INT as libc::c_int as libc::c_uint != 0 {
            let mut seqnumin: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut hash: [libc::c_char; 16] = [0; 16];
            let mut len: size_t = 0;
            let mut tmpbuf: [libc::c_char; 4] = [0; 4];
            let mut res: libc::c_int = 0;
            if input_len < 4 {
                return -(2 as libc::c_int)
            }
            len =
                (*input.offset(3 as libc::c_int as isize) as libc::c_int &
                     0xff as libc::c_int |
                     (*input.offset(2 as libc::c_int as isize) as libc::c_int
                          & 0xff as libc::c_int) << 8 as libc::c_int |
                     (*input.offset(1 as libc::c_int as isize) as libc::c_int
                          & 0xff as libc::c_int) << 16 as libc::c_int |
                     (*input.offset(0 as libc::c_int as isize) as libc::c_int
                          & 0xff as libc::c_int) << 24 as libc::c_int) as
                    size_t;
            if input_len <
                   (4 as libc::c_int as size_t).wrapping_add(len) {
                return -(2 as libc::c_int)
            }
            len =
                len.wrapping_sub((10 as libc::c_int + 2 as libc::c_int +
                                      4 as libc::c_int) as size_t);
            seqnumin =
                malloc((4 as libc::c_int as size_t).wrapping_add(len))
                    as *mut libc::c_char;
            if seqnumin.is_null() { return -(1 as libc::c_int) }
            tmpbuf[0 as libc::c_int as usize] =
                (readseqnum >> 24 & 0xff) as libc::c_char;
            tmpbuf[1 as libc::c_int as usize] =
                (readseqnum >> 16 & 0xff) as libc::c_char;
            tmpbuf[2 as libc::c_int as usize] =
                (readseqnum >> 8 & 0xff) as libc::c_char;
            tmpbuf[3 as libc::c_int as usize] =
                (readseqnum & 0xff) as libc::c_char;
            memcpy(seqnumin as *mut libc::c_void,
                   tmpbuf.as_mut_ptr() as *const libc::c_void,
                   4 as libc::c_int as size_t);
            memcpy(seqnumin.offset(4 as libc::c_int as isize) as
                       *mut libc::c_void,
                   input.offset(4 as libc::c_int as isize) as
                       *const libc::c_void, len);
            res =
                gc_hmac_md5(key as *const libc::c_void,
                            16 as libc::c_int as size_t,
                            seqnumin as *const libc::c_void,
                            len.wrapping_add(4),
                            hash.as_mut_ptr()) as libc::c_int;
            rpl_free(seqnumin as *mut libc::c_void);
            if res != 0 { return -(1 as libc::c_int) }
            if memcmp(hash.as_mut_ptr() as *const libc::c_void,
                      input.offset(input_len as
                                       isize).offset(-(4 as libc::c_int as
                                                           isize)).offset(-(2
                                                                                as
                                                                                libc::c_int
                                                                                as
                                                                                isize)).offset(-(10
                                                                                                     as
                                                                                                     libc::c_int
                                                                                                     as
                                                                                                     isize))
                          as *const libc::c_void,
                      10) == 0 as libc::c_int
                   &&
                   memcmp(b"\x00\x01\x00" as *const u8 as *const libc::c_char
                              as *const libc::c_void,
                          input.offset(input_len as
                                           isize).offset(-(4 as libc::c_int as
                                                               isize)).offset(-(2
                                                                                    as
                                                                                    libc::c_int
                                                                                    as
                                                                                    isize))
                              as *const libc::c_void,
                          2) ==
                       0 as libc::c_int &&
                   memcmp(tmpbuf.as_mut_ptr() as *const libc::c_void,
                          input.offset(input_len as
                                           isize).offset(-(4 as libc::c_int as
                                                               isize)) as
                              *const libc::c_void,
                          4) ==
                       0 as libc::c_int {
                *output_len = len;
                *output = malloc(*output_len) as *mut libc::c_char;
                if (*output).is_null() { return -(1 as libc::c_int) }
                memcpy(*output as *mut libc::c_void,
                       input.offset(4 as libc::c_int as isize) as
                           *const libc::c_void, len);
            } else { return -(1 as libc::c_int) }
        } else {
            *output_len = input_len;
            *output = malloc(input_len) as *mut libc::c_char;
            if (*output).is_null() { return -(1 as libc::c_int) }
            memcpy(*output as *mut libc::c_void, input as *const libc::c_void,
                   input_len);
        }
    }
    return 0 as libc::c_int;
}
