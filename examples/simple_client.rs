use rsasl::SASL;
use rsasl::Property;
use rsasl::error::Result;
use std::ffi::CString;

pub fn main() -> Result<()> {
    // Create & Initialize a SASL context
    let mut sasl = SASL::new()?;

    let mech = CString::new("PLAIN").expect("CString::new failed");

    // Start a new session. Finalization will automatically run when it is dropped.
    let mut session = sasl.client_start(&mech)?;

    session.set_property(Property::GSASL_AUTHID, "jas".as_bytes());
    session.set_property(Property::GSASL_PASSWORD, "secret".as_bytes());

    Ok(())
}
