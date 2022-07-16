use rsasl::error::SASLError;
use rsasl::mechanism::Authentication;
use rsasl::mechname::Mechname;
use rsasl::session::{MechanismData, Side, StepResult};
use rsasl::SASL;
use std::io::Write;
use std::mem;
use std::sync::Arc;
use rsasl::callback::EmptyCallback;

struct CustomMechanism {
    client: bool,
    step: Step,
}

enum Step {
    New,
    First,
    Second,
    Done,
}

impl CustomMechanism {
    pub fn new_client(_sasl: &SASL) -> Result<Box<dyn Authentication>, SASLError> {
        Ok(Box::new(Self {
            step: Step::New,
            client: true,
        }))
    }

    pub fn new_server(_sasl: &SASL) -> Result<Box<dyn Authentication>, SASLError> {
        Ok(Box::new(Self {
            step: Step::New,
            client: false,
        }))
    }
}

impl Authentication for CustomMechanism {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        // Do your mechanism stuff here, updating state in *self as you go.
        unimplemented!()
        /*
        match mem::replace(&mut self.step, Step::Done) {
            Step::New => {

            },
            Step::First => {}
            Step::Second => {}
            Step::Done => panic!("step() called after completion!"),
        }
         */
    }
}

const MECHNAME: &'static Mechname = unsafe { &Mechname::const_new_unchecked(b"X-CUSTOMMECH") };

use rsasl::registry::{Mechanism, MECHANISMS};

#[linkme::distributed_slice(MECHANISMS)]
pub static CUSTOMMECH: Mechanism = Mechanism {
    mechanism: MECHNAME,
    priority: 300,
    // In this situation there's one struct for both sides, however you can just as well use
    // different types than then have different `impl Authentication` instead of checking a value
    // in self.
    client: Some(CustomMechanism::new_client),
    server: Some(CustomMechanism::new_server),
    first: Side::Client,
};

pub fn main() {
    let mut rsasl = SASL::new(Arc::new(EmptyCallback));
    rsasl.register(&CUSTOMMECH);
    let available_mechanisms: Vec<&'static Mechanism> = rsasl
        .client_mech_list()
        .into_iter()
        .chain(rsasl.server_mech_list().into_iter())
        .collect();
    println!("{:#?}", available_mechanisms);

    let _client_session = rsasl.client_start(MECHNAME).unwrap();
    let _server_session = rsasl.server_start(MECHNAME).unwrap();
}
