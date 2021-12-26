
use std::ffi::CStr;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;

pub use libc;

pub mod buffer;
pub mod session;
pub mod error;
mod callback;

mod gsasl;
mod mechanisms;
mod mechname;

pub use gsasl::consts;

pub use callback::Callback;
pub use session::SessionData;
pub use buffer::SaslString;

pub use session::Step;

use crate::gsasl::consts::{GSASL_MECHANISM_PARSE_ERROR, GSASL_OK, GSASL_UNKNOWN_MECHANISM};
use crate::gsasl::gsasl::{CMechBuilder, MechContainer, Mech, Mechanism, MechanismBuilder, MechanismVTable};
pub use crate::gsasl::consts::Gsasl_property as Property;

pub use error::{
    rsasl_err_to_str,
    rsasl_errname_to_str,
};
use crate::consts::RsaslError;
use crate::error::SASLError;
use crate::gsasl::init::register_builtin_mechs;
use crate::session::Session;



// SASL Provider:
// I'm a protocol and I need to do SASL
// 1. get sasl: &SASLProvider from $somewhere
// 2. Get list of supported via sasl.get_supported_mechs()
// 3. When offered more than one by a client/server, use sasl.suggest_(client|server)_mechanism()
// 4. call session = (sasl.client_start(MECHANISM) | sasl.server_start(MECHANISM))
// 5. call session.step(data, &mut out) or session.step64(data, &mut out) as needed.
// 6. ???
// 7. PROFIT!
// (TODO: How to handle EXTERNAL?)
// Bonus minus points: sasl.wrap(data) and sasl.unwrap(data) for security layers. Prefer to not
// and instead do TLS.

#[derive(Debug)]
pub struct SASL {
    shared: Arc<Shared>,
}

impl SASL {
    pub fn new(shared: Shared) -> Self {
        Self {
            shared: Arc::new(shared),
        }
    }

    /// Returns the list of client mechanisms supported by this provider.
    ///
    pub fn client_mech_list(&self) -> impl Iterator<Item=&str> {
        let shared = self.shared.clone();
        self.shared.mechs.iter().filter_map(move |builder| {
            if builder.client().start(&shared).is_ok() {
                Some(builder.name())
            } else {
                None
            }
        })
    }

    /// Returns the list of Server Mechanisms supported by this provider.
    ///
    pub fn server_mech_list(&self) -> impl Iterator<Item=&str> {
        let shared = self.shared.clone();
        self.shared.mechs.iter().filter_map(move |builder| {
            if builder.server().start(&shared).is_ok() {
                Some(builder.name())
            } else {
                None
            }
        })
    }

    /// Suggests a mechanism to use for client-side authentication, chosen from the given list of
    /// available mechanisms.
    /// This will return Ok(None) if none of the given mechanisms are agreeable.
    pub fn suggest_client_mechanism<'a>(&self, mechs: impl Iterator<Item=&'a str>) -> Option<&str>
    {
        let shared = self.shared.clone();
        let mut min: Option<(usize, &str)> = None;
        for mech in mechs {
            let mut name = "";
            if let Some(idx) = self.shared.mechs.iter().position(|supported| {
                name = supported.name();
                mech == supported.name() && supported.client().start(&shared).is_ok()
            }) {
                if min.is_none() || min.unwrap().0 > idx {
                    min = Some((idx, name));
                }
            }
        }

        min.map(|(_, mech)| mech)
    }

    /// Suggests a mechanism to use for server-side authentication, chosen from the given list of
    /// available mechanisms.
    /// This will return Ok(None) if none of the given mechanisms are agreeable.
    pub fn suggest_server_mechanism<'a>(&self, mechs: impl Iterator<Item=&'a str>) -> Option<&str>
    {
        let shared = self.shared.clone();
        let mut min: Option<(usize, &str)> = None;
        for mech in mechs {
            let mut name = "";
            if let Some(idx) = self.shared.mechs.iter().position(|supported| {
                name = supported.name();
                mech == supported.name() && supported.server().start(&shared).is_ok()
            }) {
                if min.is_none() || min.unwrap().0 > idx {
                    min = Some((idx, name));
                }
            }
        }

        min.map(|(_, mech)| mech)
    }

    /// Returns whether there is client-side support for the given mechanism
    pub fn client_supports(&self, mech: &str) -> bool {
        self.client_mech_list().any(|supported| supported == mech)
    }

    /// Returns whether there is server-side support for the specified mechanism
    pub fn server_supports(&self, mech: &str) -> bool {
        self.server_mech_list().any(|supported| supported == mech)
    }

    /// Starts a authentication exchange as a client
    ///
    /// Depending on the mechanism chosen this may need additional data from the application, e.g.
    /// an authcid, optional authzid and password for PLAIN. To provide that data an application
    /// has to either call `set_property` before running the step that requires the data, or
    /// install a callback.
    pub fn client_start(&self, mech: &str) -> Result<Session, SASLError> {
        for builder in self.shared.mechs.iter() {
            if builder.name() == mech {
                let mechanism = builder.client().start(&self.shared)?;
                return Ok(Session::new(self.shared.callback.clone(), mechanism));
            }
        }

        Err(SASLError::UnknownMechanism)
    }

    /// Starts a authentication exchange as the server role
    ///
    /// An application acting as server will most likely need to implement a callback to check the
    /// authentication data provided by the user.
    ///
    /// See [Callback](Callback) on how to implement callbacks.
    pub fn server_start(&self, mech: &str) -> Result<Session, SASLError>
    {
        for builder in self.shared.mechs.iter() {
            if builder.name() == mech {
                let mechanism = builder.server().start(&self.shared)?;
                return Ok(Session::new(self.shared.callback.clone(), mechanism));
            }
        }

        Err(SASLError::UnknownMechanism)
    }

}

#[derive(Debug)]
// Provider
// - List of mechanisms
// - Global data
// - Callback
pub struct Shared {
    // registry: Box<dyn Registry>,
    mechs: Vec<Box<dyn Mech>>,
    callback: Option<Arc<Box<dyn Callback>>>,
}

impl Shared {
    pub fn register_cmech(&mut self, name: &'static str,
                          client: MechanismVTable,
                          server: MechanismVTable)
    {
        let mut mech = MechContainer {
            name,
            client: CMechBuilder { vtable: client },
            server: CMechBuilder { vtable: server }
        };
        mech.init();
        self.mechs.push(Box::new(mech));
    }

    pub fn register<C: 'static + MechanismBuilder, S: 'static + MechanismBuilder>(
        &mut self,
        name: &'static str,
        client: C,
        server: S)
    {
        let mut mech = Box::new(MechContainer { name, client, server });
        mech.init();
        self.mechs.push(mech);
    }

    pub fn new() -> Result<Self, RsaslError> {
        let mut this = Self {
            mechs: Vec::new(),
            callback: None,
        };

        unsafe {
            let rc = register_builtin_mechs(&mut this);
            if rc == GSASL_OK as libc::c_int {
                Ok(this)
            } else {
                Err(rc as libc::c_uint)
            }
        }
    }
}

// SASL Impl:
// I'm using a crate that wants me to do SASL
// 1. Construct a as global as possible SASLProvider with the mechanisms you want. Give it a
// custom priority list if you want.
// 2. Install a callback or provide required Property value beforehand (hey, you configured the
// list of mechanisms, you know what Properties will be required)
// 3. Pass this SASLProvider to the protocol handler
// 4. Expect callbacks if you didn't provide all Properties. Also expect callbacks if you're
// doing the server end of things

// SASL Mech:
// I need to add a Mechanism
// 1. init() -> Global constructor, called once per SASLProvider.
// 2. start() -> Instance initializer. validate that required things are present, construct a struct
//      impl Mechanism containing all state you'll carry around. This function is also used to check
//      if the current context can support your mechanism so don't do too volatile things.
// 3. step(input: Option<&[u8]>, output: impl Write) -> process input, write output, indicate new
//      state (containing how much you've written too!)
// 4. encode()/decode() security layer stuff. Please don't.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_rsasl() {
        let ctx = Shared::new().unwrap();
        println!("{:?}", ctx);
    }
}