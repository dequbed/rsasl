
use rsasl::mechname::Mechname;

use rsasl::SASL;

fn main() {
    let sasl = SASL::new();

    let presented = &[
        Mechname::const_new_unvalidated(b"LOGIN"),
        Mechname::const_new_unvalidated(b"PLAIN"),
        Mechname::const_new_unvalidated(b"GSSAPI"),
        Mechname::const_new_unvalidated(b"SCRAM-SHA-1"),
        Mechname::const_new_unvalidated(b"SCRAM-SHA-256"),
    ];

    let suggested = sasl
        .client_start_suggested(presented.iter().map(|m| *m))
        .unwrap();
    println!("Suggested: {}", suggested.get_mechname());
    assert_eq!(suggested.get_mechname().as_str(), "SCRAM-SHA-256");
}
