use std::ffi::CString;
use std::io::Cursor;
use rsasl::consts::{AuthId, GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_NO_AUTHID, GSASL_NO_CALLBACK, GSASL_NO_PASSWORD, GSASL_PASSWORD, Gsasl_property, Password};
use rsasl::{SessionData, Callback, Property, Step, session::StepResult, buffer::SaslBuffer, SASL};
use rsasl::error::SASLError;
use rsasl::mechname::Mechname;

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl Callback for OurCallback {
    fn callback(&self, session: &mut SessionData, code: Gsasl_property)
        -> Result<(), SASLError>
    {
        match code {
            GSASL_VALIDATE_SIMPLE => {
                // Access the authentication id, i.e. the username to check the password for
                let authcid = session.get_property::<AuthId>()
                    .ok_or(GSASL_NO_AUTHID)?;

                // Access the password itself
                let password = session.get_property::<Password>()
                    .ok_or(GSASL_NO_PASSWORD)?;

                // For brevity sake we use hard-coded credentials here.
                if authcid == "username"
                    && password == "secret"
                {
                    Ok(())
                } else {
                    Err(GSASL_AUTHENTICATION_ERROR.into())
                }
            },
            _ => Err(GSASL_NO_CALLBACK.into())
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new();

    sasl.install_callback(Box::new(OurCallback));

    // Authentication exchange 1
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with correct password:\n   ");
        let mut session = sasl.server_start(Mechname::try_parse(b"PLAIN").unwrap()).unwrap();
        let step_result = session.step(Some(b"\0username\0secret"), &mut out);
        print_outcome(step_result, out.into_inner());
    }
    // Authentication exchange 2
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with wrong password:\n   ");
        let mut session = sasl.server_start(Mechname::try_parse(b"PLAIN").unwrap()).unwrap();
        let step_result = session.step(Some(b"\0username\0badpass"), &mut out);
        print_outcome(step_result, out.into_inner());
    }
    // Authentication exchange 2
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with malformed data:\n   ");
        let mut session = sasl.server_start(Mechname::try_parse(b"PLAIN").unwrap()).unwrap();
        let step_result = session.step(Some(b"\0username badpass"), &mut out);
        print_outcome(step_result, out.into_inner());
    }
}

fn print_outcome(step_result: StepResult, buffer: Vec<u8>) {
    match step_result {
        Ok(Step::Done(Some(_))) => {
            println!("Authentication successful, bytes to return to client: {:?}", buffer);
        },
        Ok(Step::Done(None)) => {
            println!("Authentication successful, no data to return");
        }
        Ok(Step::NeedsMore(_)) => assert!(false, "PLAIN exchange took more than one step"),
        Err(SASLError::Gsasl(GSASL_AUTHENTICATION_ERROR))
            => println!("Authentication failed, bad username or password"),
        Err(e) => println!("Authentication errored: {}", e),
    }
}
