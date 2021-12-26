use std::io;
use std::io::Cursor;
use rsasl::consts::{AUTHID, GSASL_AUTHENTICATION_ERROR, PASSWORD};
use rsasl::{SASL, Shared, Step};
use rsasl::Step::{Done, NeedsMore};

#[test]
fn plain_client() {
    let sasl = Shared::new().unwrap();
    let prov = SASL::new(sasl);
    let mut session = prov.client_start("PLAIN").unwrap();

    let username = "testuser".to_string();
    assert_eq!(username.len(), 8);
    let password = "secret".to_string();
    assert_eq!(password.len(), 6);

    session.set_property::<AUTHID>(Box::new(username));
    session.set_property::<PASSWORD>(Box::new(password));

    let mut out = Cursor::new(Vec::new());

    // Do an authentication step. In a PLAIN exchange there is only one step, with no data.
    let step_result = session.step(None, &mut out).unwrap();

    match step_result {
        Done(Some(len)) => {
            assert_eq!(len, 1 + 8 + 1 + 6);
            let buffer = &out.into_inner()[0..len];
            // (1) "\0" + (8) "testuser" + (1) "\0" + (6) "secret"
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
    let sasl = Shared::new().unwrap();
    let prov = SASL::new(sasl);
    let mut session = prov.server_start("PLAIN").unwrap();

    let username = "testuser".to_string();
    assert_eq!(username.len(), 8);
    let password = "secret".to_string();
    assert_eq!(password.len(), 6);

    session.set_property::<AUTHID>(Box::new(username));
    session.set_property::<PASSWORD>(Box::new(password));

    let mut out = Cursor::new(Vec::new());

    match session.step(Some(b"\0testuser\0secret"), &mut out).unwrap() {
        Done(Some(_)) => {
            panic!("PLAIN mechanism wants to return data: {:?}", &out.into_inner()[..]);
        }
        Done(None) => {}
        NeedsMore(_) => panic!("PLAIN exchange took more than one step"),
    }

    let mut session = prov.server_start("PLAIN").unwrap();
    let username = "testuser".to_string();
    let password = "secret".to_string();
    session.set_property::<AUTHID>(Box::new(username));
    session.set_property::<PASSWORD>(Box::new(password));

    assert!(session.step(Some(b"\0testuser\0badpass"), &mut out)
                   .unwrap_err()
                   .matches(GSASL_AUTHENTICATION_ERROR));
}