use std::ffi::CString;
use rsasl::mechname::Mechname;
use rsasl::SASL;

pub fn main() {
    let sasl = SASL::new();
    let client_mechlist = sasl.client_mech_list();
    let server_mechlist = sasl.server_mech_list();

    println!("List of enabled CLIENT mechanisms:");
    for m in client_mechlist {
        println!(" - {}", m);
    }

    println!("\n\nList of enabled SERVER mechanisms:");
    for m in server_mechlist {
        println!(" - {}", m);
    }

    println!("\n\nLet's check if we support specific mechanisms:");
    println!("PLAIN client support: {}", sasl.client_supports(Mechname::new(b"PLAIN").unwrap()));
    println!("PLAIN server support: {}", sasl.server_supports(Mechname::new(b"PLAIN").unwrap()));

    println!("DEADBEEF client support: {}", sasl.client_supports(Mechname::new(b"DEADBEEF").unwrap()));
}
