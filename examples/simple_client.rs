use rsasl::{SASL, Property, Step};
use rsasl::error::Result;
use std::ffi::CString;

pub fn main() -> Result<()> {
    // Create & Initialize a SASL context
    let mut sasl = SASL::new()?;

    let mech = CString::new("PLAIN").expect("CString::new failed");

    // Start a new session. Finalization will automatically run when it is dropped.
    let mut session = sasl.client_start(&mech)?;

    // Set the required information for the PLAIN mechanism
    session.set_property(Property::GSASL_AUTHID, "jas".as_bytes());
    session.set_property(Property::GSASL_PASSWORD, "secret".as_bytes());

    // Run the authentication one step. In this case the client sends data first, i.e. step() gets
    // called with an empty slice for input.
    // If anything went according to plan you should see the correctly encoded output for PLAIN:
    // "\0jas\0secret"
    match session.step(&[])? {
        Step::Done(b) => { println!("{:?}", std::str::from_utf8(&b)) }
        Step::NeedsMore(b) => { println!("{:?}", std::str::from_utf8(&b)) }
    }

    session.finish();
    sasl.done();

    Ok(())
}
