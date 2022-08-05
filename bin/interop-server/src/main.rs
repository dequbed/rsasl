//! Interop testing client
//!
//! This client allows testing interoperability between different SASL implementations.

use miette::{IntoDiagnostic, WrapErr};
use rsasl::callback::{CallbackError, Context, Request, SessionCallback, SessionData};
use rsasl::mechanisms::scram::properties::*;
use rsasl::prelude::*;
use rsasl::property::*;
use rsasl::validate::{NoValidation, Validate, ValidationError};
use std::io;
use std::io::Cursor;

struct EnvCallback;
impl SessionCallback for EnvCallback {
    fn callback(
        &self,
        _session_data: &SessionData,
        context: &Context,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        fn var(key: &'static str) -> Result<String, SessionError> {
            std::env::var(key).map_err(|_| CallbackError::NoValue.into())
        }
        if request.is::<OverrideCBType>() {
            let cbtype = var("RSASL_CBNAME")?;
            request.satisfy::<OverrideCBType>(cbtype.as_str())?;
        } else if request.is::<ChannelBindings>() {
            let cbdata = var("RSASL_CBDATA")?;
            request.satisfy::<ChannelBindings>(cbdata.as_bytes())?;
        } else if request.is::<ScramStoredPassword>() {
            if let Some("username") = context.get_ref::<AuthId>() {
                request.satisfy::<ScramStoredPassword>(&ScramStoredPassword {
                    iterations: 4096,
                    salt: &[
                        0xc0, 0x3d, 0x33, 0xfd, 0xce, 0x5d, 0xed, 0x2e, 0x2a, 0xeb, 0x8e, 0xbc,
                        0x3b, 0x3d, 0x62, 0xb2,
                    ],
                    stored_key: &[
                        87, 125, 145, 236, 250, 131, 103, 74, 247, 123, 68, 218, 121, 173, 12, 23,
                        43, 85, 15, 252, 200, 80, 44, 176, 45, 246, 33, 245, 143, 247, 0, 109,
                    ],
                    server_key: &[
                        196, 31, 224, 204, 165, 244, 68, 118, 6, 197, 163, 187, 35, 70, 137, 4,
                        185, 243, 25, 19, 31, 49, 253, 198, 239, 25, 226, 58, 253, 195, 184, 185,
                    ],
                })?;
            }
        }
        Ok(())
    }
    fn validate(
        &self,
        session_data: &SessionData,
        context: &Context,
        _validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        if session_data.mechanism().mechanism.as_str() == "PLAIN" {
            let authid = context.get_ref::<AuthId>();
            let authzid = context.get_ref::<AuthzId>();
            let password = context.get_ref::<Password>();
            println!(
                "plain validation; authid={:?}, authzid={:?}, password={:?}",
                authid, authzid, password
            );
        }
        Ok(())
    }
}

pub fn main() -> miette::Result<()> {
    let config = SASLConfig::builder()
        .with_default_mechanisms()
        .with_default_sorting()
        .with_callback(EnvCallback)
        .into_diagnostic()
        .wrap_err("Failed to generate SASL config")?;

    let server = SASLServer::<NoValidation>::new(config);
    for mech in server.get_available() {
        print!("{} ", mech.mechanism.as_str());
    }
    println!();

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .into_diagnostic()
        .wrap_err("failed to read line from stdin")?;
    let selected = Mechname::new(line.trim().as_bytes())
        .into_diagnostic()
        .wrap_err(format!("selected mechanism '{}' is invalid", line))?;

    let mut session = server
        .start_suggested(selected)
        .into_diagnostic()
        .wrap_err("Failed to start SASL server session")?;

    let mut input = if session.are_we_first() {
        None
    } else {
        // Then we wait on the first line sent by the client.
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .into_diagnostic()
            .wrap_err("failed to read line from stdin")?;
        Some(line)
    };

    while {
        let mut out = Cursor::new(Vec::new());
        let (state, _) = session
            .step64(input.as_deref().map(|s| s.trim().as_bytes()), &mut out)
            .into_diagnostic()
            .wrap_err("Unexpected error occurred during stepping the session")?;
        let output = out.into_inner();

        let output =
            String::from_utf8(output).expect("base64 encoded output is somehow not valid UTF-8");
        println!("{}", output);

        state.is_running()
    } {
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .into_diagnostic()
            .wrap_err("failed to read line from stdin")?;
        input = Some(line);
    }

    Ok(())
}
