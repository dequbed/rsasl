use std::ffi::CString;
use std::io;
use rsasl_c2rust::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_NO_AUTHID, GSASL_NO_CALLBACK};
use rsasl::{
    SASL,
    Session,
    Callback,
    Property,
    Step::{Done, NeedsMore},
    session::StepResult,
    buffer::SaslBuffer
};

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl Callback<(), ()> for OurCallback {
    fn callback(sasl: &mut SASL<(), ()>, session: &mut Session<()>, prop: Property) 
        -> Result<(), u32>
    {
        match prop {
            GSASL_PASSWORD => {
                // Access the authentication id, i.e. the username to check the password for
                let authcid = session.get_property(GSASL_AUTHID)
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

        let data = CString::new(in_data.as_bytes()).unwrap();

        let step_result = session.step64(&data);

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

fn print_outcome(step_result: StepResult<SaslBuffer>) {
    match step_result {
        Ok(Done(buffer)) => {
            println!("Authentication successful, bytes to return to client: {:?}", buffer.as_ref());
        },
        Ok(NeedsMore(_)) => assert!(false, "PLAIN exchange took more than one step"),
        Err(e) if e.matches(GSASL_AUTHENTICATION_ERROR)
            => println!("Authentication failed, bad username or password"),
        Err(e) => println!("Authentication errored: {}", e),
    }
}
