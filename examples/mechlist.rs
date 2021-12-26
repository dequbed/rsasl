use rsasl::Shared;
use std::ffi::CString;

pub fn main() {
    let sasl = Shared::new_untyped().unwrap();
    let client_mechlist = sasl.client_mech_list().unwrap();
    let server_mechlist = sasl.server_mech_list().unwrap();

    println!("List of enabled CLIENT mechanisms:");
    for m in client_mechlist.iter() {
        println!(" - {}", m);
    }

    println!("\n\nList of enabled SERVER mechanisms:");
    for m in server_mechlist.iter() {
        println!(" - {}", m);
    }

    println!("\n\nLet's check if we support specific mechanisms:");
    println!("PLAIN client support: {}", sasl.client_supports(&CString::new("PLAIN").unwrap()));
    println!("PLAIN server support: {}", sasl.server_supports(&CString::new("PLAIN").unwrap()));

    println!("DEADBEEF client support: {}", sasl.client_supports(&CString::new("DEADBEEF").unwrap()));
}
