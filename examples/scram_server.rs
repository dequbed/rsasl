use std::ffi::CString;
use std::io;
use std::io::Cursor;
use rsasl::consts::{AUTHID, GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_NO_AUTHID, GSASL_NO_CALLBACK, GSASL_PASSWORD, Gsasl_property, PASSWORD};
use rsasl::{SessionData, Callback, Property, Step::{Done, NeedsMore}, session::StepResult, buffer::SaslBuffer, SASL};
use rsasl::error::SASLError;
use rsasl::error::SASLError::NoCallback;
use rsasl::mechname::Mechname;

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl Callback for OurCallback {
    fn callback(&self, session: &mut SessionData, code: Gsasl_property)
        -> Result<(), SASLError>
    {
        match code {
            GSASL_PASSWORD => {
                // Access the authentication id, i.e. the username to check the password for
                let _authcid = session.get_property_or_callback::<AUTHID>()
                    .ok_or(GSASL_NO_AUTHID)?;

                session.set_property::<PASSWORD>(Box::new("secret".to_string()));

                Ok(())
            },
            _ => Err(NoCallback { code })
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new();

    sasl.install_callback(Box::new(OurCallback));

    let mut session = sasl.server_start(Mechname::try_parse(b"SCRAM-SHA-1").unwrap()).unwrap();

    loop {
        // Read data from STDIN
        let mut in_data = String::new();
        if let Err(error) = io::stdin().read_line(&mut in_data) {
            println!("error: {}", error);
            return;
        }
        in_data.pop(); // Remove the newline char at the end of the string

        let data = Some(in_data.into_boxed_str().into_boxed_bytes());

        let mut out = Cursor::new(Vec::new());
        let step_result = session.step64(data.as_ref(), &mut out);

        match step_result {
            Ok(Done(buffer)) => {
                println!("Done: {:?}", buffer.as_ref());
                break;
            },
            Ok(NeedsMore(buffer)) => {
                println!("Data to send: {:?}", buffer.as_ref());

            }
            Err(e) => println!("{}", e),
        }
    }
}