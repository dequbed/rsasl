use ::libc;
use libc::size_t;
use crate::Shared;

extern "C" {
    static mut GSASL_VALID_MECHANISM_CHARACTERS: *const libc::c_char;
    /* Authentication functions: xstart.c, xstep.c, xfinish.c */

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char,
               _: size_t) -> libc::c_int;

    fn strspn(_: *const libc::c_char, _: *const libc::c_char)
     -> size_t;

    fn strlen(_: *const libc::c_char) -> size_t;
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
pub unsafe fn gsasl_client_suggest_mechanism(_ctx: &Shared, _mechlist: *const libc::c_char)
    -> *const libc::c_char
{
    /*
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
                if strncmp((*(*ctx).client_mechs.offset(j as isize)).name.as_ptr()
                               as *const libc::c_char,
                           mechlist.offset(i as isize), len) ==
                       0 as libc::c_int {
                    let mut sctx: *mut Gsasl_session =
                        0 as *mut Gsasl_session;
                    if gsasl_client_start(ctx,
                                          (*(*ctx).client_mechs.offset(j as
                                                                           isize)).name,
                                          &mut sctx) ==
                           GSASL_OK as libc::c_int {
                        gsasl_finish(&mut *sctx);
                        target_mech = j
                    }
                    break ;
                } else { j = j.wrapping_add(1) }
            }
            i = i.wrapping_add(len.wrapping_add(1))
        }
    }
    return if target_mech < (*ctx).n_client_mechs {
               (*(*ctx).client_mechs.offset(target_mech as isize)).name.as_ptr()
                   as *const libc::c_char
           } else { 0 as *const libc::c_char };
     */
    todo!()
}
