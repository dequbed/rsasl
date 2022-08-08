use rsasl::prelude::*;

fn main() {
    let config = SASLConfig::with_credentials(None, String::new(), String::new()).unwrap();
    let sasl = SASLClient::new(config);

    let presented = &[
        Mechname::parse(b"LOGIN").unwrap(),
        Mechname::parse(b"PLAIN").unwrap(),
        Mechname::parse(b"GSSAPI").unwrap(),
        Mechname::parse(b"SCRAM-SHA-1").unwrap(),
        Mechname::parse(b"SCRAM-SHA-256").unwrap(),
    ];

    let suggested = sasl.start_suggested(presented).unwrap();
    println!("Suggested: {}", suggested.get_mechname());
    assert_eq!(suggested.get_mechname().as_str(), "SCRAM-SHA-256");
}
