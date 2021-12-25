use std::io;
use rsasl::consts::{AUTHID, PASSWORD};
use rsasl::{SASL, Step};
use rsasl::Step::{Done, NeedsMore};

#[test]
fn plain_client() {
    let mut sasl = SASL::new().unwrap();
    let mut session = sasl.client_start("PLAIN").unwrap();

    let username = "testuser".to_string();
    assert_eq!(username.len(), 8);
    let password = "secret".to_string();
    assert_eq!(password.len(), 6);

    session.set_property::<AUTHID>(Box::new(username));
    session.set_property::<PASSWORD>(Box::new(password));


    // Do an authentication step. In a PLAIN exchange there is only one step, with no data.
    let step_result = session.step(None).unwrap();

    match step_result {
        Done(Some(buffer)) => {
            // (1) "\0" + (8) "testuser" + (1) "\0" + (6) "secret"
            assert_eq!(buffer.len(), 1 + 8 + 1 + 6);
            let (name, pass) = buffer.split_at(9);
            assert_eq!(name[0], 0);
            assert_eq!(name, b"\0testuser");
            assert_eq!(pass[0], 0);
            assert_eq!(pass, b"\0secret");
            return;
        },
        Done(None) => panic!("PLAIN exchange produced no output"),
        NeedsMore(_) => panic!("PLAIN exchange took more than one step"),
    }
}

#[test]
fn plain_server() {
    let mut sasl = SASL::new().unwrap();
    let mut session = sasl.server_start("PLAIN").unwrap();

    let username = "testuser".to_string();
    assert_eq!(username.len(), 8);
    let password = "secret".to_string();
    assert_eq!(password.len(), 6);

    session.set_property::<AUTHID>(Box::new(username));
    session.set_property::<PASSWORD>(Box::new(password));

    match session.step(Some(b"\0testuser\0secret")).unwrap() {
        Done(Some(buffer)) => {
            panic!("PLAIN mechanism wants to return data: {:?}", buffer);
        }
        Done(None) => {}
        NeedsMore(_) => panic!("PLAIN exchange took more than one step"),
    }
}