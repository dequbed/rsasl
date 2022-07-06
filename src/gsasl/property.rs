use crate::gsasl::consts::*;
use crate::gsasl::consts::{Gsasl_property, GSASL_OK};
use crate::property::*;
use crate::session::MechanismData;
use libc::{size_t, strlen};
use std::ffi::CString;
use std::sync::Arc;

pub unsafe fn gsasl_property_set(
    mut sctx: &mut MechanismData,
    mut prop: Gsasl_property,
    mut data: *const libc::c_char,
) -> libc::c_int {
    return gsasl_property_set_raw(
        sctx,
        prop,
        data,
        if !data.is_null() {
            strlen(data) as usize
        } else {
            0
        },
    );
}

pub unsafe fn gsasl_property_set_raw(
    mut sctx: &mut MechanismData,
    mut prop: Gsasl_property,
    mut data: *const libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    let bytes = std::slice::from_raw_parts(data as *const u8, len);
    let mut vec = Vec::with_capacity(len);
    vec.extend_from_slice(bytes);
    let cstring = CString::new(vec)
        .expect("gsasl_property_set_raw called with NULL-containing string")
        .into_string()
        .expect("gsasl_propery_set_raw called with non-UTF8 string");
    sctx.set_property_raw(prop, Arc::new(cstring));

    return GSASL_OK as libc::c_int;
}
/* *
 * gsasl_property_fast:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 *
 * Retrieve the data stored in the session handle for given property
 * @prop.
 *
 * The pointer is to live data, and must not be deallocated or
 * modified in any way.
 *
 * This function will not invoke the application callback.
 *
 * Return value: Return property value, if known, or NULL if no value
 *   known.
 *
 * Since: 0.2.0
 **/
unsafe fn gsasl_property_fast(
    sctx: &mut MechanismData,
    prop: Gsasl_property,
) -> *const libc::c_char {
    todo!()
}

pub unsafe fn gsasl_property_get(
    sctx: &mut MechanismData,
    prop: Gsasl_property,
) -> *const libc::c_char {
    todo!()
}

#[cfg(testn)]
mod tests {
    use super::*;
    use crate::mechanisms::plain::mechinfo::PLAIN;
    use crate::Side;
    use std::ffi::CStr;
    use std::sync::Arc;

    #[test]
    fn property_get_set() {
        let mut session = MechanismData::new(None, &PLAIN, Side::Client);

        unsafe {
            let ptr = gsasl_property_fast(&mut session, GSASL_QOP);
            assert!(ptr.is_null());
        }
        session.set_property::<Qop>(Arc::new(CString::new("testservice").unwrap()));
        let cstr = session.get_property::<Qop>();
        println!("cstr {:?}", cstr);
        unsafe {
            let ptr = gsasl_property_fast(&mut session, GSASL_QOP);
            println!("after {:?}", ptr);
            assert!(!ptr.is_null());
            let slc = std::slice::from_raw_parts(ptr as *const u8, 11);
            println!("Manual {}", std::str::from_utf8_unchecked(slc));
            let cstr = CStr::from_ptr(ptr);
            println!("fast {:?} {:?}", cstr, cstr.as_ptr());
            assert_eq!(cstr.to_str().unwrap(), "testservice");
        }
    }
}
