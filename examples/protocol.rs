use std::sync::Arc;
use rsasl::callback::EmptyCallback;
use rsasl::mechname::Mechname;

use rsasl::SASL;
use rsasl::validate::NoValidation;

fn main() {
    let sasl = SASL::new(Arc::new(EmptyCallback));

    let presented = &[
        Mechname::new(b"LOGIN").unwrap(),
        Mechname::new(b"PLAIN").unwrap(),
        Mechname::new(b"GSSAPI").unwrap(),
        Mechname::new(b"SCRAM-SHA-1").unwrap(),
        Mechname::new(b"SCRAM-SHA-256").unwrap(),
    ];

    let suggested = sasl
        .client_start_suggested(presented.iter().map(|m| *m))
        .unwrap()
        .without_channel_binding::<NoValidation>();
    println!("Suggested: {}", suggested.get_mechname());
    assert_eq!(suggested.get_mechname().as_str(), "SCRAM-SHA-256");
}
