use rsasl::callback::Callback;
use rsasl::error::SessionError;
use rsasl::mechname::Mechname;
use rsasl::property::{properties, AuthId, Password};
use rsasl::session::MechanismData;
use rsasl::session::Step::{Done, NeedsMore};
use rsasl::{Property, SASL};

use std::io;
use std::io::Cursor;
use std::sync::Arc;

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl Callback for OurCallback {
    fn callback(
        &self,
        session: &mut MechanismData,
        property: Property,
    ) -> Result<(), SessionError> {
        match property {
            properties::PASSWORD => {
                // Access the authentication id, i.e. the username to check the password for
                let _authcid = session.get_property_or_callback::<AuthId>()?;

                session.set_property::<Password>(Arc::new("secret".to_string()));

                Ok(())
            }
            _ => Err(SessionError::NoCallback { property }),
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new();

    sasl.install_callback(Arc::new(OurCallback));

    let mut session = sasl
        .server_start(Mechname::new(b"SCRAM-SHA-1").unwrap())
        .unwrap();

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
            }
            Ok(NeedsMore(buffer)) => {
                println!("Data to send: {:?}", buffer.as_ref());
            }
            Err(e) => println!("{}", e),
        }
    }
}
