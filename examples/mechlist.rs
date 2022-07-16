use rsasl::mechanism::Authentication;

use rsasl::mechname::Mechname;
use rsasl::registry::Mechanism;
use rsasl::session::{MechanismData, Side, StepResult};
use rsasl::SASL;

use std::io::Write;
use std::sync::Arc;
use rsasl::callback::EmptyCallback;

struct Test;
impl Authentication for Test {
    fn step(
        &mut self,
        _session: &mut MechanismData,
        _input: Option<&[u8]>,
        _writer: &mut dyn Write,
    ) -> StepResult {
        unimplemented!()
    }
}

const TEST: Mechanism = Mechanism {
    mechanism: unsafe { Mechname::const_new_unchecked(b"X-TEST") },
    priority: 500,
    client: Some(|_sasl| Ok(Box::new(Test))),
    server: None,
    first: Side::Client,
};

pub fn main() {
    let mut sasl = SASL::new(Arc::new(EmptyCallback));
    sasl.init();
    sasl.register(&TEST);

    println!("{:#?}", sasl);

    let client_mechlist = sasl.client_mech_list();
    let server_mechlist = sasl.server_mech_list();

    let mechlist = &rsasl::registry::MECHANISMS;
    println!("{:?}", mechlist.as_ref());

    println!("List of enabled CLIENT mechanisms:");
    for m in client_mechlist {
        println!(" - {}", m);
    }

    println!("\n\nList of enabled SERVER mechanisms:");
    for m in server_mechlist {
        println!(" - {}", m);
    }

    println!("\n\nLet's check if we support specific mechanisms:");
    println!(
        "PLAIN client support: {}",
        sasl.client_supports(Mechname::new(b"PLAIN").unwrap())
    );
    println!(
        "PLAIN server support: {}",
        sasl.server_supports(Mechname::new(b"PLAIN").unwrap())
    );

    println!(
        "DEADBEEF client support: {}",
        sasl.client_supports(Mechname::new(b"DEADBEEF").unwrap())
    );
}
