use rsasl::prelude::*;

fn main() {
    let config = SASLConfig::with_credentials(None, String::new(), String::new()).unwrap();
    let sasl = SASLClient::new(config);

    let presented = &[
        Mechname::new(b"LOGIN").unwrap(),
        Mechname::new(b"PLAIN").unwrap(),
        Mechname::new(b"GSSAPI").unwrap(),
        Mechname::new(b"SCRAM-SHA-1").unwrap(),
        Mechname::new(b"SCRAM-SHA-256").unwrap(),
    ];

    let suggested = sasl.start_suggested(presented).unwrap();
    println!("Suggested: {}", suggested.get_mechname());
    assert_eq!(suggested.get_mechname().as_str(), "SCRAM-SHA-256");
}
