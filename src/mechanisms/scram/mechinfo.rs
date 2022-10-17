use crate::alloc::boxed::Box;
use crate::mechanisms::scram::{client, server};
use crate::mechname::Mechname;
use crate::registry::{Matches, Mechanism, Name, Selection, Selector};
use crate::session::Side;

const NONCE_LEN: usize = 24;

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
#[cfg(feature = "scram-sha-1")]
pub static SCRAM_SHA1: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"SCRAM-SHA-1"),
    priority: 400,
    client: Some(|sasl, offered| {
        let mut set_cb_client_no_support = true;
        // If this fails, we def don't support cb so always set 'n' (client no support)
        if sasl
            .mech_list()
            .any(|m| m.mechanism.as_str() == "SCRAM-SHA-1-PLUS")
        {
            // If we *do* support, either the server doesn't, or we just didn't want to use it.
            set_cb_client_no_support = false;

            // if we support *and* server supports *but* it wasn't chosen, it was deliberately so
            // thus, also set 'n' (client no support) as we didn't *want* to use it.
            for name in offered {
                if name.as_str() == "SCRAM-SHA-1-PLUS" {
                    set_cb_client_no_support = true;
                }
            }
            // otherwise, none of the offered were the CB version so the server didn't support it.
            // Assumption is of course that the client *would have*. FIXME?
        }
        Ok(Box::new(client::ScramSha1Client::<NONCE_LEN>::new(
            set_cb_client_no_support,
        )))
    }),
    server: Some(|sasl| {
        let can_cb = sasl
            .mech_list()
            .any(|m| m.mechanism.as_str() == "SCRAM-SHA-1-PLUS");
        Ok(Box::new(server::ScramSha1Server::<NONCE_LEN>::new(can_cb)))
    }),
    first: Side::Client,
    select: |_| Some(Selection::Nothing(Box::new(ScramSelector1::New))),
    offer: |_| true,
};

enum ScramSelector1 {
    No,
    Yes,
    Plus,
}
impl Selector for ScramSelector1 {
    fn select(&mut self, mechname: &Mechname) -> Option<&'static Mechanism> {
        if *mechname == *SCRAM_SHA1.mechanism {
            *self = match self {
                ScramSelector1::No => {}
                ScramSelector1::Yes => {}
                ScramSelector1::Plus => {}
            }
        }
        None
    }

    fn finalize(&mut self) -> Option<&'static Mechanism> {
        todo!()
    }
}

#[cfg(feature = "scram-sha-1")]
pub static SCRAM_SHA1_PLUS: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"SCRAM-SHA-1-PLUS"),
    priority: 500,
    client: Some(|_sasl| Ok(Box::new(client::ScramSha1Client::<NONCE_LEN>::new_plus()))),
    server: Some(|_sasl| Ok(Box::new(server::ScramSha1Server::<NONCE_LEN>::new_plus()))),
    first: Side::Client,
    select: |_| Some(Matches::<Select1>::name()),
    offer: |_| true,
};

struct Select1;
impl Name for Select1 {
    fn mech() -> &'static Mechanism {
        &SCRAM_SHA1_PLUS
    }
}

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
#[cfg(feature = "scram-sha-2")]
pub static SCRAM_SHA256: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"SCRAM-SHA-256"),
    priority: 600,
    client: Some(|sasl, offered| {
        let mut set_cb_client_no_support = true;
        // If this fails, we def don't support cb so always set 'n' (client no support)
        if sasl
            .mech_list()
            .any(|m| m.mechanism.as_str() == "SCRAM-SHA-256-PLUS")
        {
            // If we *do* support, either the server doesn't, or we just didn't want to use it.
            set_cb_client_no_support = false;

            // if we support *and* server supports *but* it wasn't chosen, it was deliberately so
            // thus, also set 'n' (client no support) as we didn't *want* to use it.
            for name in offered {
                if name.as_str() == "SCRAM-SHA-256-PLUS" {
                    set_cb_client_no_support = true;
                }
            }
            // otherwise, none of the offered were the CB version so the server didn't support it.
            // Assumption is of course that the client *would have*. FIXME?
        }
        Ok(Box::new(client::ScramSha256Client::<NONCE_LEN>::new(
            set_cb_client_no_support,
        )))
    }),
    server: Some(|sasl| {
        let can_cb = sasl
            .mech_list()
            .any(|m| m.mechanism.as_str() == "SCRAM-SHA-256-PLUS");
        Ok(Box::new(server::ScramSha256Server::<NONCE_LEN>::new(
            can_cb,
        )))
    }),
    first: Side::Client,
};

#[cfg(feature = "scram-sha-2")]
pub static SCRAM_SHA256_PLUS: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"SCRAM-SHA-256-PLUS"),
    priority: 700,
    client: Some(|_sasl, _offered| {
        Ok(Box::new(client::ScramSha256Client::<NONCE_LEN>::new_plus()))
    }),
    server: Some(|_sasl| Ok(Box::new(server::ScramSha256Server::<NONCE_LEN>::new_plus()))),
    first: Side::Client,
    select: |_| Some(Matches::<Select256>::name()),
    offer: |_| true,
};

struct Select256;
impl Name for Select256 {
    fn mech() -> &'static Mechanism {
        &SCRAM_SHA256_PLUS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::default_sorter;
    use crate::config::SASLConfig;
    use crate::registry::Registry;
    use crate::sasl::SASLClient;
    use crate::test::EmptyCallback;

    #[cfg(feature = "scram-sha-1")]
    #[test]
    /// Test if SCRAM will correctly set the CB support flag depending on the offered mechanisms.
    fn scram_sha1_plus_selection() {
        static SUPPORTED: &[Mechanism] = &[SCRAM_SHA1, SCRAM_SHA1_PLUS];

        client_start(
            SUPPORTED,
            &[
                Mechname::const_new(b"SCRAM-SHA-1-PLUS"),
                Mechname::const_new(b"SCRAM-SHA-1"),
            ],
            "SCRAM-SHA-1-PLUS",
        );

        // Test inverted too
        client_start(
            SUPPORTED,
            &[
                Mechname::const_new(b"SCRAM-SHA-1"),
                Mechname::const_new(b"SCRAM-SHA-1-PLUS"),
            ],
            "SCRAM-SHA-1-PLUS",
        );
    }

    #[cfg(feature = "scram-sha-2")]
    #[test]
    /// Test if SCRAM will correctly set the CB support flag depending on the offered mechanisms.
    fn scram_sha2_plus_selection() {
        static SUPPORTED: &[Mechanism] = &[SCRAM_SHA256, SCRAM_SHA256_PLUS];

        client_start(
            SUPPORTED,
            &[
                Mechname::const_new(b"SCRAM-SHA-256-PLUS"),
                Mechname::const_new(b"SCRAM-SHA-256"),
            ],
            "SCRAM-SHA-256-PLUS",
        );

        // Test inverted too
        client_start(
            SUPPORTED,
            &[
                Mechname::const_new(b"SCRAM-SHA-256"),
                Mechname::const_new(b"SCRAM-SHA-256-PLUS"),
            ],
            "SCRAM-SHA-256-PLUS",
        );
    }

    fn client_start(supported: &'static [Mechanism], offered: &[&Mechname], expected: &str) {
        let cb = EmptyCallback;
        let config = SASLConfig::new(cb, default_sorter, Registry::with_mechanisms(supported))
            .expect("failed to construct sasl config");

        let client = SASLClient::new(config);
        let session = client
            .start_suggested(offered)
            .expect("failed to start session");
        assert_eq!(
            session.get_mechname().as_str(),
            expected,
            "expected {} to get selected, instead {} was",
            expected,
            session.get_mechname()
        );
    }
}
