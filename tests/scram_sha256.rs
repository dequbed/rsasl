use rsasl::{rsasl_err_to_str, rsasl_errname_to_str, SASL, Step};
use std::ffi::CString;
use rsasl::consts::{AUTHID, PASSWORD};
use rsasl::session::StepResult;

#[test]
pub fn test_scram_sha() {
    let mut client_sasl = SASL::new().unwrap();
    let mut server_sasl = SASL::new().unwrap();
    let mut client_session = client_sasl.client_start("SCRAM-SHA-256").unwrap();
    let mut server_session = server_sasl.server_start("SCRAM-SHA-256").unwrap();

    let authid = Box::new("testuser".to_string());
    let password = Box::new("secret".to_string());

    client_session.set_property::<AUTHID>(authid.clone());
    client_session.set_property::<PASSWORD>(password.clone());
    server_session.set_property::<AUTHID>(authid);
    server_session.set_property::<PASSWORD>(password);

    if let Step::NeedsMore(Some(data)) = client_session.step(None).map_err(|e| {
        format!("[{}]: {}",
                rsasl_errname_to_str(e).unwrap(),
                rsasl_err_to_str(e as i32).unwrap())
    }).unwrap() {
        let out = std::str::from_utf8(&data).unwrap();
        println!("Client produced: {}", out);
    } else {
        panic!("[CLIENT] SCRAM ended before first message!");
    }
}
