use std::any::{Any, TypeId};
use std::collections::HashMap;
use rsasl::callback::{Context, Request, SessionCallback, SessionData};
use rsasl::prelude::{SASLConfig, SASLServer, Validation, Registry, SASLClient, SessionError, Session, SASLError, State, Property};
use rsasl::property::{AuthId, AuthzId, Password};

#[derive(Debug, Clone)]
pub struct Callback {
    authid: String,
    authzid: Option<String>,
    password: Vec<u8>,
}
impl SessionCallback for Callback {
    fn callback(&self, session_data: &SessionData, context: &Context, request: &mut Request) -> Result<(), SessionError> {
        request
            .satisfy::<AuthId>(&self.authid)?
            .satisfy::<Password>(&self.password)?;

        if let Some(z) = self.authzid.as_deref() {
            request.satisfy::<AuthzId>(z)?;
        }

        Ok(())
    }
}
impl Default for Callback {
    fn default() -> Self {
        Self {
            authid: "testuser".to_string(),
            authzid: None,
            password: b"secret".to_vec(),
        }
    }
}

struct V;
impl Validation for V {
    type Value = ();
}

fn run_single<V: Validation>(mut client: Session, mut server: Session<V>) -> Result<Option<V::Value>, SessionError> {
    let mut client_input = Vec::new();
    let mut server_input = Vec::new();
    let mut client_state;
    let mut server_state = State::Running;

    if client.are_we_first() {
        client_state = client.step(None, &mut server_input)?;
    } else {
        server_state = server.step(None, &mut client_input)?;
        client_state = client.step(Some(&client_input[..]), &mut server_input)?;
        client_input.clear();
    }

    while {
        if server_state.is_running() {
            server_state = server.step(Some(&server_input[..]), &mut client_input)?;
            server_input.clear();
        }

        if client_state.is_running() {
            client_state = client.step(Some(&client_input[..]), &mut server_input)?;
            client_input.clear();
        }

        client_state.is_running() && server_state.is_running()
    } {}

    if client_state.is_running() {
        // Final call if server considers exchange done, but client doesn't
        client.step(None, &mut server_input)?;
    }
    if server_state.is_running() {
        // Final call for the reverse case
        server.step(None, &mut client_input)?;
    }

    Ok(server.validation())
}

fn setup<V: Validation>(client: SASLClient, server: SASLServer<V>) -> Result<(Session, Session<V>), SASLError> {
    let offered = server.get_available().into_iter().map(|m| m.mechanism);
    let client_session = client.start_suggested_iter(offered)?;
    let selected = client_session.get_mechname();
    let server_session = server.start_suggested(selected)?;
    eprintln!("Setup successful!");
    eprintln!("Selected: {selected}");
    Ok((client_session, server_session))
}

#[test]
fn run_all() {
    let mut errored = false;
    let callback = Callback::default();
    let server_registry = Registry::default();
    let server_config = SASLConfig::builder()
        .with_registry(server_registry)
        .with_callback(callback.clone())
        .expect("failed to construct SASLConfig");
    let server = SASLServer::<V>::new(server_config.clone());
    let m: Vec<_> = server.get_available().into_iter().filter_map(|mechanism| {
        // Only test implementations against each other that have both client & server-side available
        if mechanism.client().is_some() {
            Some(Box::leak(Box::new([*mechanism])))
        } else {
            None
        }
    }).collect();

    'outer: for mechanism_slice in m {
        let client_registry = Registry::with_mechanisms(mechanism_slice);
        let client_config = SASLConfig::builder()
            .with_registry(client_registry)
            .with_callback(callback.clone())
            .expect("failed to construct SASLConfig");
        let client = SASLClient::new(client_config);
        let server = SASLServer::<V>::new(server_config.clone());
        eprintln!("====================");
        match setup(client, server) {
            Ok((client_session, server_session)) => {
                match
                 run_single(client_session, server_session) {
                    Err(error) => {
                        errored = true;
                        eprintln!("Exchange FAILED");
                        eprintln!("Error: ({error:?}) — {error}");
                    }
                    Ok(None) => {
                        errored = true;
                        eprintln!("Exchange FAILED");
                        eprintln!("Error: Server failed to validate");
                    }
                    Ok(Some(())) => {
                        eprintln ! ("Exchange OK");
                    }
                }
            },
            Err(error) => {
                eprintln!("Setup failed: {error:?}");
                continue 'outer;
            }
        }
        eprintln!("====================");
    }

    if errored {
        panic!("One or more exchanges failed to run through.")
    }
}