//! Mechanism registry *only available with feature `unstable_custom_mechanism`*
//!
//! The Registry allows users to configure which mechanisms are enabled and their order of
//! importance.
//! By default the registry will collect and enable all known Mechanisms. It will prefer external
//! (i.e. coming from 3rd party downstream crates) Mechanisms over the built-in ones and prefers
//! built-in ones roughly by their cryptographic strength, preferring SSO-enabled mechanism.
//! An exception is made for DIGEST_MD5 and CRAM_MD5 which are always given the least priority.
//!
//! So the rough default priority goes:
//! - OPENID20, SAML20, GS2-*, GSSAPI
//! - SCRAM-SHA-256(-PLUS)
//! - SCRAM-SHA-1(-PLUS)
//! - PLAIN, SECURID
//! - LOGIN
//! - ANONYMOUS, EXTERNAL
//! - CRAM_MD5, DIGEST_MD5
//!
//! ## Static compile-time registry using dtolnay's `linkme` crate
//!
// TODO: Explain static registry
//!
//! Note: Due to [rustc issue #47384](https://github.com/rust-lang/rust/issues/47384) the static(s)
//! for your Mechanism MUST be marked `pub` and be reachable by dependent crates, otherwise they
//! may be silently dropped by the compiler.

use crate::alloc::boxed::Box;
use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use core::cmp::Ordering;
use core::fmt;

use crate::config::SASLConfig;
use crate::error::SASLError;
pub use crate::session::Side;
#[allow(unused_imports)]
#[cfg(feature = "registry_static")]
pub use registry_static::*;

pub type StartFn = fn() -> Result<Box<dyn Authentication>, SASLError>;
pub type ServerStartFn = fn(sasl: &SASLConfig) -> Result<Box<dyn Authentication>, SASLError>;

#[non_exhaustive]
#[derive(Copy, Clone)]
/// Mechanism Implementation
///
/// **NOTE:** The API of custom mechanisms is *not stable*. You MUST NOT rely on API
/// stability over minor version releases of rsasl.
///
/// All mechanisms need to export a `static Mechanism` to be usable by rsasl, see the
/// [registry module documentation][crate::registry] for details.
pub struct Mechanism {
    /// The Mechanism served by this implementation.
    pub mechanism: &'static Mechname,

    pub(crate) priority: usize,

    pub(crate) client: Option<StartFn>,
    pub(crate) server: Option<ServerStartFn>,

    #[cfg_attr(not(feature = "provider"), allow(unused))]
    pub(crate) first: Side,

    pub(crate) select: fn(bool) -> Option<Selection>,
    #[allow(dead_code)]
    pub(crate) offer: fn(bool) -> bool,
}

#[cfg(feature = "unstable_custom_mechanism")]
impl Mechanism {
    /// Construct a Mechanism constant for custom mechanisms
    ///
    /// **NOTE:** The API of custom mechanisms is *not stable*. You MUST NOT rely on API
    /// stability over minor version releases of rsasl.
    #[must_use]
    pub const fn build(
        mechanism: &'static Mechname,
        priority: usize,
        client: Option<StartFn>,
        server: Option<ServerStartFn>,
        first: Side,
        select: fn(bool) -> Option<Selection>,
        offer: fn(bool) -> bool,
    ) -> Self {
        Self {
            mechanism,
            priority,
            client,
            server,
            first,
            select,
            offer,
        }
    }
}

impl Mechanism {
    #[must_use]
    pub fn client(&self) -> Option<Result<Box<dyn Authentication>, SASLError>> {
        self.client.map(|f| f())
    }

    #[must_use]
    pub fn server(&self, sasl: &SASLConfig) -> Option<Result<Box<dyn Authentication>, SASLError>> {
        self.server.map(|f| f(sasl))
    }

    #[must_use]
    fn select(&self, cb: bool) -> Option<Selection> {
        (self.select)(cb)
    }
}

impl fmt::Debug for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mechanism")
            .field("name", &self.mechanism)
            .field("has client", &self.client.is_some())
            .field("has server", &self.server.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mechanism.as_str())
    }
}

#[derive(Debug, Clone)]
/// Registry of available mechanism implementations
///
/// This struct provides a common interface by abstracting the various ways mechanisms may be
/// registered.
pub struct Registry {
    static_mechanisms: &'static [Mechanism],
}

#[cfg(any(test, feature = "config_builder", feature = "testutils"))]
mod config {
    use super::Registry;
    use crate::registry::Mechanism;

    #[cfg(feature = "config_builder")]
    impl Registry {
        #[inline(always)]
        #[must_use]
        /// Construct a registry with the given set of mechanisms, overwriting the default set.
        pub const fn with_mechanisms(mechanisms: &'static [Mechanism]) -> Self {
            Self {
                static_mechanisms: mechanisms,
            }
        }

        pub(crate) fn credentials(authzid: bool) -> Self {
            static CRED_AUTHZID: &[Mechanism] = &[
                #[cfg(feature = "scram-sha-2")]
                crate::mechanisms::scram::SCRAM_SHA512,
                #[cfg(feature = "scram-sha-2")]
                crate::mechanisms::scram::SCRAM_SHA256,
                #[cfg(feature = "scram-sha-1")]
                crate::mechanisms::scram::SCRAM_SHA1,
                #[cfg(feature = "plain")]
                crate::mechanisms::plain::PLAIN,
            ];

            static CRED: &[Mechanism] = &[
                #[cfg(feature = "scram-sha-2")]
                crate::mechanisms::scram::SCRAM_SHA512,
                #[cfg(feature = "scram-sha-2")]
                crate::mechanisms::scram::SCRAM_SHA256,
                #[cfg(feature = "scram-sha-1")]
                crate::mechanisms::scram::SCRAM_SHA1,
                #[cfg(feature = "plain")]
                crate::mechanisms::plain::PLAIN,
                #[cfg(feature = "login")]
                crate::mechanisms::login::LOGIN,
            ];

            // Only ever enable LOGIN if no authzid is provided
            let mechanisms = if authzid { CRED_AUTHZID } else { CRED };
            Self::with_mechanisms(mechanisms)
        }
    }

    #[cfg(feature = "registry_static")]
    impl Default for Registry {
        fn default() -> Self {
            Self::with_mechanisms(&super::registry_static::MECHANISMS)
        }
    }

    #[cfg(not(feature = "registry_static"))]
    impl Default for Registry {
        fn default() -> Self {
            static BUILTIN: &[Mechanism] = &[
                #[cfg(feature = "scram-sha-2")]
                crate::mechanisms::scram::SCRAM_SHA512,
                #[cfg(feature = "scram-sha-2")]
                crate::mechanisms::scram::SCRAM_SHA256,
                #[cfg(feature = "scram-sha-1")]
                crate::mechanisms::scram::SCRAM_SHA1,
                #[cfg(feature = "plain")]
                crate::mechanisms::plain::PLAIN,
                #[cfg(feature = "login")]
                crate::mechanisms::login::LOGIN,
                #[cfg(feature = "anonymous")]
                crate::mechanisms::anonymous::ANONYMOUS,
                #[cfg(feature = "external")]
                crate::mechanisms::external::EXTERNAL,
                #[cfg(feature = "xoauth2")]
                crate::mechanisms::xoauth2::XOAUTH2,
                #[cfg(feature = "oauthbearer")]
                crate::mechanisms::oauthbearer::OAUTHBEARER,
            ];

            Self::with_mechanisms(BUILTIN)
        }
    }
}

pub type MechanismIter<'a> = core::slice::Iter<'a, Mechanism>;
#[allow(dead_code)]
impl Registry {
    #[inline(always)]
    pub(crate) fn get_mechanisms<'a>(&self) -> MechanismIter<'a> {
        self.static_mechanisms.iter()
    }

    pub(crate) fn select<'a>(
        &self,
        cb: bool,
        offered: impl Iterator<Item = &'a Mechname>,
        mut fold: impl FnMut(Option<&'static Mechanism>, &'static Mechanism) -> Ordering,
    ) -> Result<(Box<dyn Authentication>, &'static Mechanism), SASLError> {
        // This looks like a terrible double-allocation as Selection contains a `Box<dyn Selector>`,
        // but for most of the mechanisms the Selector is a ZST meaning the Box doesn't allocate.
        // Only if the selector has to keep state (e.g. the non-PLUS SCRAM ones have to change
        // their behaviour depending on what mechanisms the server offered for their GS2 header)
        // the Box has to make an allocation.
        let mut selectors: Vec<Selection> =
            self.get_mechanisms().filter_map(|m| m.select(cb)).collect();

        for o in offered {
            for s in &mut selectors {
                s.select(o);
            }
        }

        let (mut s, m) = selectors
            .into_iter()
            .filter_map(|mut s| s.done().map(|m| (s, m)))
            .fold(None, |acc, (s, m)| {
                let accmech = acc.as_ref().map(|(_, m)| *m);
                match fold(accmech, m) {
                    // `Greater` means the first parameter (accmech) was preferable — even if None.
                    Ordering::Greater => acc,
                    // `Equal` is undefined behaviour, but we're just going for `Less` because
                    // we don't have to check for `accmech` being `None` then.
                    Ordering::Equal |
                    // `Less` means the second parameter (m) was preferable
                    Ordering::Less => Some((s,m))
                }
            })
            .ok_or(SASLError::NoSharedMechanism)?;
        s.finalize().map(|a| (a, m))
    }
}

#[cfg(feature = "registry_static")]
mod registry_static {
    use super::Mechanism;

    //noinspection RsTypeCheck
    #[linkme::distributed_slice]
    pub static MECHANISMS: [Mechanism];
}
#[cfg(not(feature = "registry_static"))]
mod registry_static {
    use super::Mechanism;

    #[allow(dead_code)]
    pub static MECHANISMS: [Mechanism; 0] = [];
}

#[allow(dead_code)]
mod selector {
    use super::{Authentication, Box, Mechanism, Mechname, SASLError};
    use alloc::marker::PhantomData;
    pub trait Selector {
        fn select(&mut self, mechname: &Mechname) -> Option<&'static Mechanism>;
        fn done(&mut self) -> Option<&'static Mechanism>;
        fn finalize(&mut self) -> Result<Box<dyn Authentication>, SASLError>;
    }

    #[non_exhaustive]
    pub enum Selection {
        Nothing(Box<dyn Selector>),
        Done(&'static Mechanism),
    }
    impl Selection {
        pub(super) fn select(&mut self, mechname: &Mechname) {
            if let Self::Nothing(ref mut selector) = self {
                if let Some(m) = selector.select(mechname) {
                    *self = Self::Done(m);
                }
            }
        }

        pub(super) fn done(&mut self) -> Option<&'static Mechanism> {
            match self {
                Self::Nothing(selector) => selector.done(),
                Self::Done(m) => Some(m),
            }
        }

        pub(super) fn finalize(&mut self) -> Result<Box<dyn Authentication>, SASLError> {
            match self {
                Self::Nothing(selector) => selector.finalize(),
                Self::Done(m) => m.client().unwrap(),
            }
        }
    }

    pub trait Named {
        fn mech() -> &'static Mechanism;
    }
    #[repr(transparent)]
    pub struct Matches<T>(PhantomData<T>);
    impl<T: Named + 'static> Matches<T> {
        #[must_use]
        pub fn name() -> Selection {
            Selection::Nothing(Box::new(Self(PhantomData)))
        }
    }
    impl<T: Named> Selector for Matches<T> {
        fn select(&mut self, mechname: &Mechname) -> Option<&'static Mechanism> {
            let m = T::mech();
            if *mechname == *m.mechanism {
                Some(m)
            } else {
                None
            }
        }
        fn done(&mut self) -> Option<&'static Mechanism> {
            None
        }
        fn finalize(&mut self) -> Result<Box<dyn Authentication>, SASLError> {
            let m = T::mech();
            (m.client.unwrap())()
        }
    }
}

pub use selector::*;
