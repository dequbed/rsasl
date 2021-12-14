use ::libc;
use libc::size_t;
use crate::consts::GSASL_OK;
use crate::SASL;
use crate::gsasl::gsasl::{Gsasl_mechanism};

extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: size_t) -> *mut libc::c_void;
}

#[no_mangle]
pub unsafe fn gsasl_register(
    ctx: &mut SASL,
    mech: &Gsasl_mechanism,
) -> libc::c_int
{
    ctx.register_cmech(mech.name, mech.client, mech.server);
    /*
    let mut tmp: *mut Gsasl_mechanism = 0 as *mut Gsasl_mechanism;
    if (*mech).client.init.is_none() ||
           (*mech).client.init.expect("non-null function pointer")(ctx) ==
               GSASL_OK as libc::c_int {
        tmp =
            realloc((*ctx).client_mechs as *mut libc::c_void,
                    ::std::mem::size_of::<Gsasl_mechanism>()
                        .wrapping_mul((*ctx).n_client_mechs.wrapping_add(1)))
                as *mut Gsasl_mechanism;
        if tmp.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
        memcpy(&mut *tmp.offset((*ctx).n_client_mechs as isize) as *mut Gsasl_mechanism as *mut libc::c_void,
               mech as *const libc::c_void,
               ::std::mem::size_of::<Gsasl_mechanism>());
        (*ctx).client_mechs = tmp;
        (*ctx).n_client_mechs = (*ctx).n_client_mechs.wrapping_add(1)
    }
    if (*mech).server.init.is_none() ||
           (*mech).server.init.expect("non-null function pointer")(ctx) ==
               GSASL_OK as libc::c_int {
        tmp = realloc((*ctx).server_mechs as *mut libc::c_void,
                    (::std::mem::size_of::<Gsasl_mechanism>())
                        .wrapping_mul((*ctx).n_server_mechs.wrapping_add(1)))
                as *mut Gsasl_mechanism;
        if tmp.is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
        memcpy(&mut *tmp.offset((*ctx).n_server_mechs as isize) as
                   *mut Gsasl_mechanism as *mut libc::c_void,
               mech as *const libc::c_void,
               ::std::mem::size_of::<Gsasl_mechanism>());
        (*ctx).server_mechs = tmp;
        (*ctx).n_server_mechs = (*ctx).n_server_mechs.wrapping_add(1)
    }
     */
    return GSASL_OK as libc::c_int;
}
