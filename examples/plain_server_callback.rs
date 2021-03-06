use std::ffi::CString;
use rsasl::{
    SASL,
    Session,
    Callback,
    Property,
    ReturnCode,
    Step,
    session::StepResult,
    buffer::SaslBuffer
};

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl Callback<(), ()> for OurCallback {
    fn callback(sasl: &mut SASL<(), ()>, session: &mut Session<()>, prop: Property) 
        -> Result<(), ReturnCode> 
    {
        match prop {
            Property::GSASL_VALIDATE_SIMPLE => {
                // Access the authentication id, i.e. the username to check the password for
                let authcid = session.get_property(Property::GSASL_AUTHID)
                    .ok_or(ReturnCode::GSASL_NO_AUTHID)?;

                // Access the password itself
                let password = session.get_property(Property::GSASL_PASSWORD)
                    .ok_or(ReturnCode::GSASL_NO_PASSWORD)?;

                // For brevity sake we use hard-coded credentials here.
                if authcid == CString::new("username").unwrap().as_ref()
                    && password == CString::new("secret").unwrap().as_ref()
                {
                    Ok(())
                } else {
                    Err(ReturnCode::GSASL_AUTHENTICATION_ERROR)
                }
            },
            _ => Err(ReturnCode::GSASL_NO_CALLBACK)
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new_untyped().unwrap();

    sasl.install_callback::<OurCallback>();

    // Authentication exchange 1
    {
        print!("Authenticating to server with correct password:\n   ");
        let mut session = sasl.server_start("PLAIN").unwrap();
        let step_result = session.step(b"\0username\0secret");
        print_outcome(step_result);
    }
    // Authentication exchange 2
    {
        print!("Authenticating to server with wrong password:\n   ");
        let mut session = sasl.server_start("PLAIN").unwrap();
        let step_result = session.step(b"\0username\0badpass");
        print_outcome(step_result);
    }
    // Authentication exchange 2
    {
        print!("Authenticating to server with malformed data:\n   ");
        let mut session = sasl.server_start("PLAIN").unwrap();
        let step_result = session.step(b"\0username badpass");
        print_outcome(step_result);
    }
}

fn print_outcome(step_result: StepResult<SaslBuffer>) {
    match step_result {
        Ok(Step::Done(buffer)) => {
            println!("Authentication successful, bytes to return to client: {:?}", buffer.as_ref());
        },
        Ok(Step::NeedsMore(_)) => assert!(false, "PLAIN exchange took more than one step"),
        Err(e) if e.matches(ReturnCode::GSASL_AUTHENTICATION_ERROR) 
            => println!("Authentication failed, bad username or password"),
        Err(e) => println!("Authentication errored: {}", e),
    }
}
