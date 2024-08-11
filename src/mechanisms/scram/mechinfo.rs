use crate::alloc::boxed::Box;
use crate::error::SASLError;
use crate::mechanism::Authentication;
use crate::mechanisms::scram::{client, server};
use crate::mechname::Mechname;
use crate::registry::{Matches, Mechanism, Named, Selection, Selector};
use crate::session::Side;

const NONCE_LEN: usize = 24;

#[cfg(feature = "scram-sha-1")]
mod scram_sha1 {
    use super::{
        client, server, Authentication, Box, Matches, Mechanism, Mechname, Named, SASLError,
        Selection, Selector, Side, NONCE_LEN,
    };

    #[cfg_attr(
        feature = "registry_static",
        linkme::distributed_slice(crate::registry::MECHANISMS)
    )]
    #[cfg(feature = "scram-sha-1")]
    pub static SCRAM_SHA1: Mechanism = Mechanism {
        mechanism: Mechname::const_new(b"SCRAM-SHA-1"),
        priority: 400,
        client: Some(|| Ok(Box::new(client::ScramSha1Client::<NONCE_LEN>::new(true)))),
        server: Some(|sasl| {
            let can_cb = sasl
                .mech_list()
                .any(|m| m.mechanism.as_str() == "SCRAM-SHA-1-PLUS");
            Ok(Box::new(server::ScramSha1Server::<NONCE_LEN>::new(can_cb)))
        }),
        first: Side::Client,
        select: |cb| {
            Some(if cb {
                Selection::Nothing(Box::new(ScramSelector1::No))
            } else {
                Matches::<Select1>::name()
            })
        },
        offer: |_| true,
    };

    struct Select1;
    impl Named for Select1 {
        fn mech() -> &'static Mechanism {
            &SCRAM_SHA1
        }
    }

    #[derive(Copy, Clone, Debug)]
    enum ScramSelector1 {
        /// No SCRAM-SHA1 found yet
        No,
        /// Only SCRAM-SHA1 but not -PLUS found
        Bare,
        /// SCRAM-SHA1-PLUS found.
        Plus,
    }
    impl Selector for ScramSelector1 {
        fn select(&mut self, mechname: &Mechname) -> Option<&'static Mechanism> {
            if *mechname == *SCRAM_SHA1.mechanism {
                *self = match *self {
                    Self::No => Self::Bare,
                    x => x,
                }
            } else if *mechname == *SCRAM_SHA1_PLUS.mechanism {
                *self = Self::Plus;
            }
            None
        }

        fn done(&mut self) -> Option<&'static Mechanism> {
            match self {
                Self::No => None,
                _ => Some(&SCRAM_SHA1),
            }
        }

        fn finalize(&mut self) -> Result<Box<dyn Authentication>, SASLError> {
            Ok(Box::new(match self {
                Self::Bare => client::ScramSha1Client::<NONCE_LEN>::new(false),
                Self::Plus => client::ScramSha1Client::<NONCE_LEN>::new(true),
                Self::No => unreachable!(),
            }))
        }
    }

    pub static SCRAM_SHA1_PLUS: Mechanism = Mechanism {
        mechanism: Mechname::const_new(b"SCRAM-SHA-1-PLUS"),
        priority: 500,
        client: Some(|| Ok(Box::new(client::ScramSha1Client::<NONCE_LEN>::new_plus()))),
        server: Some(|_sasl| Ok(Box::new(server::ScramSha1Server::<NONCE_LEN>::new_plus()))),
        first: Side::Client,
        select: |cb| {
            if cb {
                Some(Matches::<Select1Plus>::name())
            } else {
                None
            }
        },
        offer: |_| true,
    };

    struct Select1Plus;
    impl Named for Select1Plus {
        fn mech() -> &'static Mechanism {
            &SCRAM_SHA1_PLUS
        }
    }
}
#[cfg(feature = "scram-sha-1")]
pub use scram_sha1::*;

#[cfg(feature = "scram-sha-2")]
mod scram_sha256 {
    use super::{
        client, server, Authentication, Box, Matches, Mechanism, Mechname, Named, SASLError,
        Selection, Selector, Side, NONCE_LEN,
    };

    #[cfg_attr(
        feature = "registry_static",
        linkme::distributed_slice(crate::registry::MECHANISMS)
    )]
    pub static SCRAM_SHA256: Mechanism = Mechanism {
        mechanism: Mechname::const_new(b"SCRAM-SHA-256"),
        priority: 600,
        client: Some(|| Ok(Box::new(client::ScramSha256Client::<NONCE_LEN>::new(true)))),
        server: Some(|sasl| {
            let can_cb = sasl
                .mech_list()
                .any(|m| m.mechanism.as_str() == "SCRAM-SHA-256-PLUS");
            Ok(Box::new(server::ScramSha256Server::<NONCE_LEN>::new(
                can_cb,
            )))
        }),
        first: Side::Client,
        select: |cb| {
            Some(if cb {
                Selection::Nothing(Box::new(ScramSelector256::No))
            } else {
                Matches::<Select256>::name()
            })
        },
        offer: |_| true,
    };

    struct Select256;
    impl Named for Select256 {
        fn mech() -> &'static Mechanism {
            &SCRAM_SHA256
        }
    }

    #[derive(Copy, Clone, Debug)]
    enum ScramSelector256 {
        /// No SCRAM-SHA256 found yet
        No,
        /// Only SCRAM-SHA256 but not -PLUS found
        Bare,
        /// SCRAM-SHA256-PLUS found.
        Plus,
    }
    impl Selector for ScramSelector256 {
        fn select(&mut self, mechname: &Mechname) -> Option<&'static Mechanism> {
            if *mechname == *SCRAM_SHA256.mechanism {
                *self = match *self {
                    Self::No => Self::Bare,
                    x => x,
                }
            } else if *mechname == *SCRAM_SHA256_PLUS.mechanism {
                *self = Self::Plus;
            }
            None
        }

        fn done(&mut self) -> Option<&'static Mechanism> {
            match self {
                Self::No => None,
                _ => Some(&SCRAM_SHA256),
            }
        }

        fn finalize(&mut self) -> Result<Box<dyn Authentication>, SASLError> {
            Ok(Box::new(match self {
                Self::Bare => client::ScramSha256Client::<NONCE_LEN>::new(false),
                Self::Plus => client::ScramSha256Client::<NONCE_LEN>::new(true),
                Self::No => unreachable!(),
            }))
        }
    }

    pub static SCRAM_SHA256_PLUS: Mechanism = Mechanism {
        mechanism: Mechname::const_new(b"SCRAM-SHA-256-PLUS"),
        priority: 700,
        client: Some(|| Ok(Box::new(client::ScramSha256Client::<NONCE_LEN>::new_plus()))),
        server: Some(|_sasl| Ok(Box::new(server::ScramSha256Server::<NONCE_LEN>::new_plus()))),
        first: Side::Client,
        select: |cb| {
            if cb {
                Some(Matches::<Select256Plus>::name())
            } else {
                None
            }
        },
        offer: |_| true,
    };

    struct Select256Plus;
    impl Named for Select256Plus {
        fn mech() -> &'static Mechanism {
            &SCRAM_SHA256_PLUS
        }
    }
}
#[cfg(feature = "scram-sha-2")]
pub use scram_sha256::*;

#[cfg(feature = "scram-sha-2")]
mod scram_sha512 {
    use super::{
        client, server, Authentication, Box, Matches, Mechanism, Mechname, Named, SASLError,
        Selection, Selector, Side, NONCE_LEN,
    };

    #[cfg_attr(
        feature = "registry_static",
        linkme::distributed_slice(crate::registry::MECHANISMS)
    )]
    pub static SCRAM_SHA512: Mechanism = Mechanism {
        mechanism: Mechname::const_new(b"SCRAM-SHA-512"),
        priority: 600,
        client: Some(|| Ok(Box::new(client::ScramSha512Client::<NONCE_LEN>::new(true)))),
        server: Some(|sasl| {
            let can_cb = sasl
                .mech_list()
                .any(|m| m.mechanism.as_str() == "SCRAM-SHA-512-PLUS");
            Ok(Box::new(server::ScramSha512Server::<NONCE_LEN>::new(
                can_cb,
            )))
        }),
        first: Side::Client,
        select: |cb| {
            Some(if cb {
                Selection::Nothing(Box::new(ScramSelector512::No))
            } else {
                Matches::<Select512>::name()
            })
        },
        offer: |_| true,
    };

    struct Select512;
    impl Named for Select512 {
        fn mech() -> &'static Mechanism {
            &SCRAM_SHA512
        }
    }

    #[derive(Copy, Clone, Debug)]
    enum ScramSelector512 {
        /// No SCRAM-SHA512 found yet
        No,
        /// Only SCRAM-SHA512 but not -PLUS found
        Bare,
        /// SCRAM-SHA512-PLUS found.
        Plus,
    }
    impl Selector for ScramSelector512 {
        fn select(&mut self, mechname: &Mechname) -> Option<&'static Mechanism> {
            if *mechname == *SCRAM_SHA512.mechanism {
                *self = match *self {
                    Self::No => Self::Bare,
                    x => x,
                }
            } else if *mechname == *SCRAM_SHA512_PLUS.mechanism {
                *self = Self::Plus;
            }
            None
        }

        fn done(&mut self) -> Option<&'static Mechanism> {
            match self {
                Self::No => None,
                _ => Some(&SCRAM_SHA512),
            }
        }

        fn finalize(&mut self) -> Result<Box<dyn Authentication>, SASLError> {
            Ok(Box::new(match self {
                Self::Bare => client::ScramSha512Client::<NONCE_LEN>::new(false),
                Self::Plus => client::ScramSha512Client::<NONCE_LEN>::new(true),
                Self::No => unreachable!(),
            }))
        }
    }

    pub static SCRAM_SHA512_PLUS: Mechanism = Mechanism {
        mechanism: Mechname::const_new(b"SCRAM-SHA-512-PLUS"),
        priority: 700,
        client: Some(|| Ok(Box::new(client::ScramSha512Client::<NONCE_LEN>::new_plus()))),
        server: Some(|_sasl| Ok(Box::new(server::ScramSha512Server::<NONCE_LEN>::new_plus()))),
        first: Side::Client,
        select: |cb| {
            if cb {
                Some(Matches::<Select512Plus>::name())
            } else {
                None
            }
        },
        offer: |_| true,
    };

    struct Select512Plus;
    impl Named for Select512Plus {
        fn mech() -> &'static Mechanism {
            &SCRAM_SHA512_PLUS
        }
    }
}
#[cfg(feature = "scram-sha-2")]
pub use scram_sha512::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback::SessionCallback;
    use crate::config::SASLConfig;
    use crate::registry::Registry;
    use crate::sasl::SASLClient;

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
        struct ThisCB;
        impl SessionCallback for ThisCB {
            fn enable_channel_binding(&self) -> bool {
                true
            }
        }
        let cb = ThisCB;
        let config = SASLConfig::new(cb, Registry::with_mechanisms(supported))
            .expect("failed to construct sasl config");

        let client = SASLClient::new(config);
        let session = client
            .start_suggested(offered.iter())
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
