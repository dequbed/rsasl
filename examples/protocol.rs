use rsasl::{SASL};
use rsasl::error::SASLError;
use rsasl::mechname::Mechname;
use rsasl::session::Session;

fn main() {
    let sasl = SASL::new();

    let a = "LOGIN PLAIN GSSAPI".split_whitespace()
        .map(|s| Mechname::new(s.as_bytes()))
        .filter_map(|s| s.ok());
    let presented = &[
        Mechname::const_new_unchecked(b"LOGIN"),
        Mechname::const_new_unchecked(b"PLAIN"),
        Mechname::const_new_unchecked(b"GSSAPI"),
        Mechname::const_new_unchecked(b"SCRAM-SHA-1"),
        Mechname::const_new_unchecked(b"SCRAM-SHA-256"),
    ];

    let suggested = sasl.client_start_suggested(presented.iter().map(|m| *m)).unwrap();
    println!("Suggested: {}", suggested.get_mechanism());
    assert_eq!(suggested.get_mechanism().as_str(), "SCRAM-SHA-256");
}