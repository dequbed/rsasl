use rsasl::{rsasl_err_to_str, rsasl_errname_to_str, SASL, Step};
use std::ffi::CString;
use std::io::Cursor;
use rsasl::consts::{AUTHID, PASSWORD};
use rsasl::mechname::Mechname;
use rsasl::session::StepResult;

#[test]
pub fn test_scram_sha() {
    let mut client_sasl = SASL::new();
    let mut server_sasl = SASL::new();
    let mut client_session = client_sasl.client_start(Mechname::try_parse(b"SCRAM-SHA-256").unwrap()).unwrap();
    let mut server_session = server_sasl.server_start(Mechname::try_parse(b"SCRAM-SHA-256").unwrap()).unwrap();

    let authid = Box::new("testuser".to_string());
    let password = Box::new("secret".to_string());

    client_session.set_property::<AUTHID>(authid.clone());
    client_session.set_property::<PASSWORD>(password.clone());
    server_session.set_property::<AUTHID>(authid);
    server_session.set_property::<PASSWORD>(password);

    let mut out = Cursor::new(Vec::new());
    let data: Option<&[u8]> = None;
    if let Step::NeedsMore(Some(len)) = client_session.step(data, &mut out).unwrap() {
        let buffer = out.into_inner();
        let str = std::str::from_utf8(&buffer).unwrap();
        println!("Client produced: {}", str);
    } else {
        panic!("[CLIENT] SCRAM ended before first message!");
    }
}
