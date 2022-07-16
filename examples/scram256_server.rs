use std::io;
use std::io::Cursor;
use std::sync::Arc;
use rsasl::callback::{CallbackError, Request, SessionCallback};
use rsasl::context::Context;
use rsasl::error::SessionError;
use rsasl::mechanisms::scram::properties::PasswordHash;
use rsasl::mechname::Mechname;
use rsasl::property::AuthId;
use rsasl::SASL;
use rsasl::session::SessionData;
use rsasl::validate::{NoValidation, Validate, ValidationError};

struct OurCallback;
impl SessionCallback for OurCallback {
    fn callback(&self, _session_data: &SessionData, context: &Context, request: &mut Request<'_>) -> Result<(), SessionError> {
        if request.is::<PasswordHash>() {
            let username = context.get_ref::<AuthId>()
                .ok_or(SessionError::CallbackError(CallbackError::NoCallback))?;
            if username == "username" {
                todo!()
                //request.satisfy::<PasswordHash>()
            }
        }

        Ok(())
    }
}

pub fn main() {
    let mut sasl = SASL::new(Arc::new(OurCallback));

    let mut session = sasl
        .server_start(Mechname::new(b"SCRAM-SHA-256").unwrap())
        .unwrap()
        .without_channel_binding::<NoValidation>();

    loop {
        // Read data from STDIN
        let mut in_data = String::new();
        if let Err(error) = io::stdin().read_line(&mut in_data) {
            println!("error: {}", error);
            return;
        }

        let data = in_data.trim().to_string(); // Remove the newline char at the end of the string
        let mut out = Cursor::new(Vec::new());

        let (state, written) = session.step(Some(data.as_bytes()), &mut out).unwrap();
    }
}
