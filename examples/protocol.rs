use rsasl::{SASL, Shared};
use rsasl::session::Session;

struct ProtocolHandler {
    sasl_handler: SASL,
    authentication: Option<Session>,
}

impl ProtocolHandler {
    fn handle_auth(&mut self, mechs: &[&str]) -> Result<(), rsasl::SaslError> {
        let mech = self.sasl_handler.suggest_client_mechanism(mechs.iter())?;
        if let Some(mech) = mech {
        }
        todo!()
    }
}

fn main() {
    let sasl = Shared::new().unwrap();
    let provider = SASL::new(sasl);

    let handler = ProtocolHandler {
        sasl_handler: provider,
        authentication: None,
    };
}