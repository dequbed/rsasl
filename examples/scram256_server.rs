use rsasl::callback::Callback;
use rsasl::error::SessionError;
use rsasl::mechname::Mechname;
use rsasl::property::{properties, AuthId, Password, Property};
use rsasl::session::MechanismData;
use rsasl::session::Step::{Done, NeedsMore};
use rsasl::SASL;

use std::io;
use std::io::Cursor;
use std::sync::Arc;

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
                let authcid = session.get_property_or_callback::<AuthId>()?;
                println!("auth'ing user {:?}", authcid);

                session.set_property::<Password>(Arc::new("secret".to_string()));

                Ok(())
            }
            _ => Err(SessionError::NoProperty { property }),
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new();

    sasl.install_callback(Arc::new(OurCallback));

    let mut session = sasl
        .server_start(Mechname::new(b"SCRAM-SHA-256").unwrap())
        .unwrap();

    loop {
        // Read data from STDIN
        let mut in_data = String::new();
        if let Err(error) = io::stdin().read_line(&mut in_data) {
            println!("error: {}", error);
            return;
        }
        let in_data = in_data.trim().to_string(); // Remove the newline char at the end of the string

        let data = Some(in_data.into_boxed_str().into_boxed_bytes());
        let mut out = Cursor::new(Vec::new());

        let step_result = session.step(data.as_ref(), &mut out);

        match step_result {
            Ok(Done(Some(_))) => {
                let buffer = out.into_inner();
                let output = std::str::from_utf8(buffer.as_ref()).unwrap();
                println!("Done: {:?}", output);
                break;
            }
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
                let buffer = out.into_inner();
                let output = std::str::from_utf8(buffer.as_ref()).unwrap();
                println!("{} || {}", e, output);
                break;
            }
        }
    }
}
