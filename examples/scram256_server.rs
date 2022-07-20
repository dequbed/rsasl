use rsasl::callback::{CallbackError, Request, SessionCallback, Context};
use rsasl::prelude::{ServerConfig, SessionError};
use rsasl::mechanisms::scram::properties::PasswordHash;
use rsasl::mechname::Mechname;
use rsasl::property::AuthId;
use rsasl::prelude::SessionData;
use rsasl::validate::NoValidation;
use rsasl::prelude::SASLServer;
use std::io;
use std::io::Cursor;
use std::sync::Arc;

struct OurCallback;
impl SessionCallback for OurCallback {
    fn callback(
        &self,
        _session_data: &SessionData,
        context: &Context,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        if request.is::<PasswordHash>() {
            let username = context
                .get_ref::<AuthId>()
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
    let config = ServerConfig::builder().with_defaults().with_callback(Box::new(OurCallback), false).unwrap();
    let sasl = SASLServer::<NoValidation>::new(Arc::new(config));

    let mut session = sasl
        .start_suggested(&[Mechname::new(b"SCRAM-SHA-256").unwrap()])
        .unwrap();

    loop {
        // Read data from STDIN
        let mut in_data = String::new();
        if let Err(error) = io::stdin().read_line(&mut in_data) {
            println!("error: {}", error);
            return;
        }

        let data = in_data.trim().to_string(); // Remove the newline char at the end of the string
        let mut out = Cursor::new(Vec::new());

        let (_state, _written) = session.step(Some(data.as_bytes()), &mut out).unwrap();
    }
}
