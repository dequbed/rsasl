use std::ffi::CString;
use std::io;
use rsasl::consts::{GSASL_AUTHID, GSASL_NO_AUTHID,
                           GSASL_NO_CALLBACK, GSASL_PASSWORD};
use rsasl::{
    SASL,
    Session,
    Callback,
    Property,
    Step::{Done, NeedsMore},
};

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl Callback<(), ()> for OurCallback {
    fn callback(_sasl: &mut SASL<(), ()>, session: &mut Session<()>, prop: Property)
        -> Result<(), u32>
    {
        match prop {
            GSASL_PASSWORD => {
                // Access the authentication id, i.e. the username to check the password for
                let _authcid = session.get_property_or_callback(GSASL_AUTHID)
                    .ok_or(GSASL_NO_AUTHID)?;

                session.set_property(GSASL_PASSWORD, "secret".as_bytes());

                Ok(())
            },
            _ => Err(GSASL_NO_CALLBACK)
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new_untyped().unwrap();

    sasl.install_callback::<OurCallback>();

    let mut session = sasl.server_start("SCRAM-SHA-256").unwrap();

    loop {
        // Read data from STDIN
        let mut in_data = String::new();
        if let Err(error) = io::stdin().read_line(&mut in_data) {
            println!("error: {}", error);
            return;
        }
        in_data.pop(); // Remove the newline char at the end of the string

        let data = in_data.into_boxed_str().into_boxed_bytes();

        let step_result = session.step(&data);

        match step_result {
            Ok(Done(buffer)) => {
                let output = std::str::from_utf8(buffer.as_ref()).unwrap();
                println!("Done: {:?}", output);
                break;
            },
            Ok(NeedsMore(buffer)) => {
                let output = std::str::from_utf8(buffer.as_ref()).unwrap();
                println!("Data to send: {:?}", output);
            }
            Err(e) => {
                println!("{}", e);
                break;
            },
        }
    }
}