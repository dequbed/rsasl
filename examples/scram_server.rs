use std::ffi::CString;
use std::io;
use std::io::Cursor;
use std::sync::Arc;
use rsasl::callback::Callback;
use rsasl::error::SASLError;
use rsasl::error::SASLError::NoCallback;
use rsasl::mechname::Mechname;
use rsasl::{Property, SASL};
use rsasl::property::{AuthId, Password, properties};
use rsasl::session::SessionData;
use rsasl::session::Step::{Done, NeedsMore};

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl Callback for OurCallback {
    fn provide_prop(&self, session: &mut SessionData, property: Property)
        -> Result<(), SASLError>
    {
        match property {
            properties::PASSWORD => {
                // Access the authentication id, i.e. the username to check the password for
                let _authcid = session.get_property_or_callback::<AuthId>()?;

                session.set_property::<Password>(Box::new("secret".to_string()));

                Ok(())
            },
            _ => Err(NoCallback { property })
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new();

    sasl.install_callback(Arc::new(OurCallback));

    let mut session = sasl.server_start(Mechname::new(b"SCRAM-SHA-1").unwrap()).unwrap();

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