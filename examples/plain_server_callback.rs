use rsasl::callback::Callback;
use rsasl::error::SessionError;
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, Password};
use rsasl::session::Step::Done;
use rsasl::session::{MechanismData, Step, StepResult};
use rsasl::validate::{validations, Validation};
use rsasl::SASL;
use std::io::Cursor;
use std::sync::Arc;

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl Callback for OurCallback {
    fn validate(
        &self,
        session: &mut MechanismData,
        validation: Validation,
        mechanism: &Mechname,
    ) -> Result<(), SessionError> {
        println!("Asked to validate mech: {} w/ {}", mechanism, validation);
        match validation {
            validations::SIMPLE => {
                // Access the authentication id, i.e. the username to check the password for
                let authcid = session
                    .get_property::<AuthId>()
                    .ok_or_else(SessionError::no_property::<AuthId>)?;

                // Access the password itself
                let password = session
                    .get_property::<Password>()
                    .ok_or_else(SessionError::no_property::<Password>)?;

                // For brevity sake we use hard-coded credentials here.
                if authcid.as_str() == "username" && password.as_str() == "secret" {
                    Ok(())
                } else {
                    Err(SessionError::AuthenticationFailure)
                }
            }
            _ => Err(SessionError::NoValidate { validation }),
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new();

    sasl.install_callback(Arc::new(OurCallback));

    // Authentication exchange 1
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with correct password:\n   ");
        let mut session = sasl.server_start(Mechname::new(b"PLAIN").unwrap()).unwrap();
        let step_result = session.step(Some(b"\0username\0secret"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert_eq!(step_result.unwrap(), Done(None));
    }
    // Authentication exchange 2
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with wrong password:\n   ");
        let mut session = sasl.server_start(Mechname::new(b"PLAIN").unwrap()).unwrap();
        let step_result = session.step(Some(b"\0username\0badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert_eq!(
            step_result.unwrap_err(),
            SessionError::AuthenticationFailure
        );
    }
    // Authentication exchange 2
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with malformed data:\n   ");
        let mut session = sasl.server_start(Mechname::new(b"PLAIN").unwrap()).unwrap();
        let step_result = session.step(Some(b"\0username badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert!(step_result.unwrap_err().is_mechanism_error());
    }
}

fn print_outcome(step_result: &StepResult, buffer: Vec<u8>) {
    match step_result {
        Ok(Step::Done(Some(_))) => {
            println!(
                "Authentication successful, bytes to return to client: {:?}",
                buffer
            );
        }
        Ok(Step::Done(None)) => {
            println!("Authentication successful, no data to return");
        }
        Ok(Step::NeedsMore(_)) => assert!(false, "PLAIN exchange took more than one step"),
        Err(SessionError::AuthenticationFailure) => {
            println!("Authentication failed, bad username or password")
        }
        Err(e) => println!("Authentication errored: {}", e),
    }
}
