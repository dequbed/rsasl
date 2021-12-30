use std::ffi::CString;
use std::io;
use std::io::Cursor;
use rsasl::consts::{AUTHID, GSASL_AUTHID, GSASL_NO_AUTHID, GSASL_NO_CALLBACK, GSASL_PASSWORD, Gsasl_property, PASSWORD};
use rsasl::{SessionData, Callback, Property, Step::{Done, NeedsMore}, SASL};
use rsasl::error::SASLError;
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
            _ => Err(GSASL_NO_CALLBACK.into())
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new();

    sasl.install_callback(Box::new(OurCallback));

    let mut session = sasl.server_start(Mechname::try_parse(b"SCRAM-SHA-256").unwrap()).unwrap();

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

        let step_result = session.step(data.as_ref(), &mut out);

        match step_result {
            Ok(Done(Some(_))) => {
                let buffer = out.into_inner();
                let output = std::str::from_utf8(buffer.as_ref()).unwrap();
                println!("Done: {:?}", output);
                break;
            },
            Ok(Done(None)) => {
                println!("Done, but mechanism wants to send no data to other party");
                break;
            }
            Ok(NeedsMore(Some(_))) => {
                let buffer = out.into_inner();
                let output = std::str::from_utf8(buffer.as_ref()).unwrap();
                println!("Data to send: {:?}", output);
            }
            Ok(NeedsMore(None)) => {
                println!("Needs more data, but mechanism wants to send no data to other party");
                break;
            }
            Err(e) => {
                println!("{}", e);
                break;
            },
        }
    }
}