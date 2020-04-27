use rsasl::{SASL, Property, Step, Session, ReturnCode};
use rsasl::sys::{Gsasl, Gsasl_session};
use rsasl::error::Result;
use std::ffi::CString;

extern "C" fn callback(ctx: *mut Gsasl, sctx: *mut Gsasl_session, prop: Property) -> i32 {
    let sasl = SASL::from_ptr(ctx);
    let mut sess = Session::from_ptr(sctx);

    let mut rc = ReturnCode::GSASL_NO_CALLBACK;

    match prop {
        Property::GSASL_PASSWORD => {
            // The only valid password is sesam.
            // Real code would check the AUTHID and AUTHZID first.
            sess.set_property(prop, b"sesam");
            rc = ReturnCode::GSASL_OK;
        },
        _ => {},
    }

    return rc as i32;
}

pub fn main() -> Result<()> {
    // Create & Initialize a SASL context
    let mut sasl = SASL::new()?;

    sasl.install_callback(Some(callback));

    let c = CString::new("PLAIN").expect("CString::new failed");
    let mut session = sasl.server_start(&c)?;

    match session.step(b"\0jas\0sesam")? {
        Step::Done(b) => { println!("Done: {:?}", std::str::from_utf8(&b)) }
        Step::NeedsMore(b) => { println!("NeedsMore: {:?}", std::str::from_utf8(&b)) }
    }

    let authid = session.get_property_fast(Property::GSASL_AUTHID);
    let authzid = session.get_property_fast(Property::GSASL_AUTHID);
    println!("AUTHID {:?}", authid.to_str());
    println!("AUTHZID {:?}", authzid.to_str());

    session.finish();
    sasl.done();

    Ok(())
}
