use ::libc;
use libc::size_t;
use crate::gsasl::consts::GSASL_OK;
use crate::gsasl::gsasl::{Gsasl, Gsasl_session};

extern "C" {
    #[no_mangle]
    static mut GSASL_VALID_MECHANISM_CHARACTERS: *const libc::c_char;
    /* Authentication functions: xstart.c, xstep.c, xfinish.c */
    #[no_mangle]
    fn gsasl_finish(sctx: *mut Gsasl_session);
    #[no_mangle]
    fn gsasl_client_start(ctx: *mut Gsasl, mech: *const libc::c_char,
                          sctx: *mut *mut Gsasl_session) -> libc::c_int;
    #[no_mangle]
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char,
               _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn strspn(_: *const libc::c_char, _: *const libc::c_char)
     -> libc::c_ulong;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}

/* *
 * gsasl_client_suggest_mechanism:
 * @ctx: libgsasl handle.
 * @mechlist: input character array with SASL mechanism names,
 *   separated by invalid characters (e.g. SPC).
 *
 * Given a list of mechanisms, suggest which to use.
 *
 * Return value: Returns name of "best" SASL mechanism supported by
 *   the libgsasl client which is present in the input string, or
 *   NULL if no supported mechanism is found.
 **/
#[no_mangle]
pub unsafe extern "C" fn gsasl_client_suggest_mechanism(mut ctx: *mut Gsasl,
                                                        mut mechlist:
                                                            *const libc::c_char)
 -> *const libc::c_char {
    let mut mechlist_len: size_t = 0; /* ~ no target */
    let mut target_mech: size_t = 0;
    let mut i: size_t = 0;
    mechlist_len =
        if !mechlist.is_null() {
            strlen(mechlist) as usize
        } else { 0 };
    target_mech = (*ctx).n_client_mechs;
    i = 0 as libc::c_int as size_t;
    while i < mechlist_len {
        let mut len = 0;
        len =
            strspn(mechlist.offset(i as isize),
                   GSASL_VALID_MECHANISM_CHARACTERS);
        if len == 0 {
            i = i.wrapping_add(1)
        } else {
            let mut j: size_t = 0;
            /* Assumption: the mechs array is sorted by preference
	   * from low security to high security. */
            j =
                if target_mech < (*ctx).n_client_mechs {
                    target_mech.wrapping_add(1)
                } else { 0 };
            while j < (*ctx).n_client_mechs {
                if strncmp((*(*ctx).client_mechs.offset(j as isize)).name,
                           mechlist.offset(i as isize), len) ==
                       0 as libc::c_int {
                    let mut sctx: *mut Gsasl_session =
                        0 as *mut Gsasl_session;
                    if gsasl_client_start(ctx,
                                          (*(*ctx).client_mechs.offset(j as
                                                                           isize)).name,
                                          &mut sctx) ==
                           GSASL_OK as libc::c_int {
                        gsasl_finish(sctx);
                        target_mech = j
                    }
                    break ;
                } else { j = j.wrapping_add(1) }
            }
            i =
                (i as
                     libc::c_ulong).wrapping_add(len.wrapping_add(1 as
                                                                      libc::c_int
                                                                      as
                                                                      libc::c_ulong))
                    as size_t as size_t
        }
    }
    return if target_mech < (*ctx).n_client_mechs {
               (*(*ctx).client_mechs.offset(target_mech as isize)).name
           } else { 0 as *const libc::c_char };
}
