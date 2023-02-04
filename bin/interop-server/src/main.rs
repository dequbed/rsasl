//! Interop testing client
//!
//! This client allows testing interoperability between different SASL implementations.

use miette::{miette, Diagnostic, IntoDiagnostic, MietteHandler, ReportHandler, WrapErr};
use rsasl::callback::{CallbackError, Context, Request, SessionCallback, SessionData};
use rsasl::mechanisms::scram::properties::*;
use rsasl::prelude::*;
use rsasl::property::*;
use rsasl::validate::{Validate, ValidationError};
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::sync::Arc;

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
                request.satisfy::<ScramStoredPassword>(&ScramStoredPassword::new(
                    4096,
                    &[
                        0xc0, 0x3d, 0x33, 0xfd, 0xce, 0x5d, 0xed, 0x2e, 0x2a, 0xeb, 0x8e, 0xbc,
                        0x3b, 0x3d, 0x62, 0xb2,
                    ],
                    &[
                        87, 125, 145, 236, 250, 131, 103, 74, 247, 123, 68, 218, 121, 173, 12, 23,
                        43, 85, 15, 252, 200, 80, 44, 176, 45, 246, 33, 245, 143, 247, 0, 109,
                    ],
                    &[
                        196, 31, 224, 204, 165, 244, 68, 118, 6, 197, 163, 187, 35, 70, 137, 4,
                        185, 243, 25, 19, 31, 49, 253, 198, 239, 25, 226, 58, 253, 195, 184, 185,
                    ],
                ))?;
            }
        }
        Ok(())
    }
    fn validate(
        &self,
        session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        if matches!(
            session_data.mechanism().mechanism.as_str(),
            "PLAIN" | "LOGIN"
        ) {
            let authid = context
                .get_ref::<AuthId>()
                .ok_or(ValidationError::MissingRequiredProperty)?;
            let authzid = context.get_ref::<AuthzId>().map(|s| s.to_string());
            let password = context
                .get_ref::<Password>()
                .ok_or(ValidationError::MissingRequiredProperty)?;
            validate.finalize::<InteropValidation>(InteropValidation {
                authid: authid.to_string(),
                authzid,
                password: Some(password.to_vec()),
            });
        } else if session_data
            .mechanism()
            .mechanism
            .as_str()
            .starts_with("SCRAM-")
        {
            let authid = context
                .get_ref::<AuthId>()
                .ok_or(ValidationError::MissingRequiredProperty)?;
            let authzid = context.get_ref::<AuthzId>().map(|s| s.to_string());
            validate.finalize::<InteropValidation>(InteropValidation {
                authid: authid.to_string(),
                authzid,
                password: None,
            });
        }
        Ok(())
    }
}

struct InteropValidation {
    authid: String,
    authzid: Option<String>,
    password: Option<Vec<u8>>,
}
impl Display for InteropValidation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("VALID authid=")?;
        f.write_str(self.authid.as_str())?;

        if let Some(ref authz) = self.authzid {
            f.write_str(" authzid=")?;
            f.write_str(authz.as_str())?;
        }

        if let Some(ref pass) = self.password {
            f.write_str(" password=")?;
            if let Ok(s) = std::str::from_utf8(pass.as_slice()) {
                f.write_str(s)?;
            } else {
                pass.fmt(f)?;
            }
        }

        Ok(())
    }
}

impl Validation for InteropValidation {
    type Value = Self;
}

fn handle_client(
    config: Arc<SASLConfig>,
    read_end: impl io::Read,
    mut write_end: impl io::Write,
) -> miette::Result<()> {
    let mut lines = BufReader::new(read_end).lines();

    let server = SASLServer::<InteropValidation>::new(config);

    // First, write all supported mechanisms to the other end
    for mech in server.get_available() {
        write_end
            .write_all(mech.mechanism.as_bytes())
            .into_diagnostic()
            .wrap_err("failed to write supported mechanism")?;
        write_end
            .write_all(b" ")
            .into_diagnostic()
            .wrap_err("failed to write supported mechanism")?;
    }
    write_end
        .write_all(b"\n")
        .into_diagnostic()
        .wrap_err("failed to write supported mechanism")?;

    let selected = lines
        .next()
        .ok_or_else(|| miette!("Client disconnected!"))?
        .into_diagnostic()
        .wrap_err("failed to decode selected mechanism line")?;

    let mut parts = selected.split_whitespace();
    let mechname_part = parts
        .next()
        .ok_or_else(|| miette!("protocol error: Client must send selected mechanism"))?;

    let mechanism = Mechname::parse(mechname_part.as_bytes())
        .into_diagnostic()
        .wrap_err("failed to parse selected Mechanism")?;

    println!("client selected [{}]", &mechanism);

    let mut session = server
        .start_suggested(mechanism)
        .into_diagnostic()
        .wrap_err(format!("[{}] failed to start server session", mechanism))?;

    let mut buffer = Vec::new();

    let mut input_data = if session.are_we_first() {
        None
    } else {
        let data = if let Some(initial_data) = parts.next() {
            Cow::Borrowed(initial_data)
        } else {
            // If we expect initial data and didn't get any yet, send a single '-' to indicate
            // that to the client. Otherwise it's impossible for the client to distinguish
            // between a hanging server and a server waiting for more data.
            write_end
                .write_all(b"-\n")
                .into_diagnostic()
                .wrap_err("failed to write empty response")?;

            let input = lines
                .next()
                .ok_or_else(|| miette!("Client disconnected!"))?
                .into_diagnostic()
                .wrap_err("Protocol error: Client must send valid UTF-8 lines")?;

            Cow::Owned(input)
        };
        Some(data)
    };

    while {
        let input = input_data.as_deref().map(|s| s.as_bytes());
        let state = session
            .step64(input, &mut buffer)
            .map_err(|error| {
                let error_fmt = format!("ERR {:?}: {}\n", &error, &error);
                let _ = write_end.write_all(error_fmt.as_bytes());
                error
            })
            .into_diagnostic()
            .wrap_err("failed to step mechanism")?;

        if state.has_sent_message() {
            buffer.push(b'\n');
            write_end
                .write_all(&buffer[..])
                .expect("failed to write output");
            buffer.clear();
        }

        state.is_running()
    } {
        let line = lines
            .next()
            .ok_or_else(|| miette!("Client disconnected!"))?
            .into_diagnostic()
            .wrap_err("Protocol error: Client must send valid UTF-8 lines")?;
        input_data = Some(Cow::Owned(line))
    }

    let out = if let Some(v) = session.validation() {
        Cow::Owned(format!("OK {}\n", v))
    } else {
        Cow::Borrowed("ERR NOTVALID\n")
    };

    write_end
        .write_all(out.as_bytes())
        .into_diagnostic()
        .wrap_err("failed to send outcome string")?;

    Ok(())
}

struct PrintError<'a, H> {
    handler: &'a H,
    error: &'a dyn Diagnostic,
}

impl<'a, H: ReportHandler> Debug for PrintError<'a, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.handler.debug(self.error, f)
    }
}

pub fn main() -> miette::Result<()> {
    let report_handler = MietteHandler::new();
    let addr = std::env::var("RSASL_TEST_REMOTE")
        .map(Cow::Owned)
        .unwrap_or(Cow::Borrowed("localhost:62185"));

    let listener = TcpListener::bind(addr.as_ref())
        .unwrap_or_else(|_| panic!("[addr={}] failed to bind tcp stream", addr));

    let config = SASLConfig::builder()
        .with_default_mechanisms()
        .with_callback(EnvCallback)
        .into_diagnostic()
        .wrap_err("Failed to generate SASL config")?;

    for stream in listener.incoming() {
        let stream = stream
            .into_diagnostic()
            .wrap_err("failed to open stream")
            .and_then(|stream| {
                let write_end = stream.try_clone().expect("failed to clone TcpStream");
                handle_client(config.clone(), stream, write_end)
            });
        if let Err(report) = stream {
            let p = PrintError {
                handler: &report_handler,
                error: report.as_ref(),
            };
            println!("{p:?}");
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    #[test]
    // Ensure that the stdlib .split_whitespace() method handles tailing whitespace as we expect
    // it to.
    fn test_split_whitespace() {
        let lineA = "MECHANISM ";
        let mut it = lineA.split_whitespace();
        assert_eq!(it.next(), Some("MECHANISM"));
        assert_eq!(it.next(), None);

        let lineB = "MECHANISM InitialData";
        let mut it = lineB.split_whitespace();
        assert_eq!(it.next(), Some("MECHANISM"));
        assert_eq!(it.next(), Some("InitialData"));

        let lineC = "MECHANISM";
        let mut it = lineC.split_whitespace();
        assert_eq!(it.next(), Some("MECHANISM"));
        assert_eq!(it.next(), None);
    }
}
