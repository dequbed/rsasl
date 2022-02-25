use base64::write::EncoderWriter;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::sync::Arc;

use crate::error::SessionError;
use crate::gsasl::consts::{property_from_code, Gsasl_property};
use crate::mechanism::Authentication;
use crate::property::PropertyQ;
use crate::validate::*;
use crate::{Callback, Mechanism, Mechname, Property};

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}

pub struct Session {
    mechanism: Box<dyn Authentication>,
    session_data: SessionData,
    // TODO: Channel Binding data should probably be queried via a callback as well. That ways
    //       protocol crates can easier provide that data on demand. That pattern can use static
    //       generics too since the protocol crate is the one holding the Session.
}

impl Session {
    pub(crate) fn new(
        callback: Option<Arc<dyn Callback>>,
        global_properties: Arc<HashMap<Property, Arc<dyn Any + Send + Sync>>>,
        mechdesc: &'static Mechanism,
        mechanism: Box<dyn Authentication>,
        side: Side,
    ) -> Self {
        Self {
            mechanism,
            session_data: SessionData::new(callback, global_properties, mechdesc, side),
        }
    }

    pub fn set_property<P: PropertyQ>(&mut self, item: Arc<P::Item>) -> Option<Arc<P::Item>> {
        self.session_data.set_property::<P>(item).map(|old| {
            old.downcast()
                .expect("old session data value was of bad type")
        })
    }

    pub fn get_property<P: PropertyQ>(&mut self) -> Option<Arc<P::Item>> {
        self.session_data.get_property::<P>()
    }

    pub fn get_mechname(&self) -> &'static Mechname {
        self.session_data.mechanism.mechanism
    }

    pub fn are_we_first(&self) -> bool {
        self.session_data.side == self.session_data.mechanism.first
    }

    pub fn has_security_layer(&self) -> bool {
        todo!()
    }
}

#[cfg(feature = "provider")]
impl Session {
    /// Perform one step of SASL authentication.
    ///
    /// *requires feature `provider`*
    ///
    /// A protocol implementation calls this method with any data provided by the other party,
    /// returning any response data written to the other party until after a Ok([`Step::Done`]) or
    /// [`StepResult::Err`] is returned.
    ///
    /// To generate the first batch of data call this method with an input of `None`. If a `Step`
    /// with a value of Some (i.e. `Step::Done(Some(_))` or `Step::NeedsMore(Some(_))`) is
    /// returned the selected mechanism is initiated by your side and you can provide this data
    /// to the other party.
    /// If the Step contains a `None` the other party has to provide the initial batch of data.
    ///
    /// Not all protocols support both ClientFirst and ServerFirst Mechanisms, i.e. mechanisms in
    /// which the client sends the first batch of data and mechanisms in which the server sends
    /// the first batch of data. Refer to the documentation of the protocol in question on how to
    /// indicate to the other party that they have to provide the first batch of data.
    ///
    /// Keep in mind that SASL makes a distinction between zero-sized data to send (a Step
    /// containing `Some(0)`) and no data to send (a `Step` containing `None`).
    pub fn step(&mut self, input: Option<impl AsRef<[u8]>>, writer: &mut impl Write) -> StepResult {
        if let Some(input) = input {
            self.mechanism
                .step(&mut self.session_data, Some(input.as_ref()), writer)
        } else {
            self.mechanism.step(&mut self.session_data, None, writer)
        }
    }

    /// Provide channel binding data for mechanisms
    ///
    /// Some mechanisms can make use of channel binding to verify that the underlying (encrypted)
    /// connection is in fact with the expected party and not being MitM'ed.
    /// To allow this behaviour the channel binding data needs to be made available with a call to
    /// this method.
    pub fn set_channel_binding_data(&mut self, name: &'static str, value: Box<[u8]>) {
        self.session_data.set_channel_binding_data(name, value);
    }
}

#[cfg(feature = "provider_base64")]
impl Session {
    /// Perform one step of SASL authentication, base64 encoded.
    ///
    /// *requires feature `provider_base64`*
    ///
    /// This is a utility function wrapping [`Session::step`] to consume and produce
    /// base64-encoded data. See the documentation of `step` for details on how this function
    /// operates.
    ///
    /// Requiring base64-encoded SASL data is common in line-based or textual formats, such as
    /// SMTP, IMAP, XMPP and IRCv3.
    /// Refer to your protocol documentation if SASL data needs to be base64 encoded.
    pub fn step64(
        &mut self,
        input: Option<impl AsRef<[u8]>>,
        writer: &mut impl Write,
    ) -> StepResult {
        let input = input
            .map(|inp| base64::decode_config(inp.as_ref(), base64::STANDARD))
            .transpose()?;
        let mut writer64 = EncoderWriter::new(writer, base64::STANDARD);
        self.step(input, &mut writer64)
    }
}

pub struct SessionData {
    // TODO: Move caching out of SessionData and into Callback. That makes no_std or situations
    //       where caching makes no sense much more reasonable to implement.
    pub(crate) callback: Option<Arc<dyn Callback>>,
    property_cache: HashMap<Property, Arc<dyn Any + Send + Sync>>,
    global_properties: Arc<HashMap<Property, Arc<dyn Any + Send + Sync>>>,
    mechanism: &'static Mechanism,
    side: Side,
    channel_binding_data: Option<(&'static str, Box<[u8]>)>,
}

impl Debug for SessionData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionData")
            .field("has callback", &self.callback.is_some())
            .field("property cache", &self.property_cache)
            .field("global properties", &self.global_properties)
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
/// The outcome of a single step in the authentication exchange
///
/// Since SASL is multi-step each step can either complete the exchange or require more steps to be
/// performed. In both cases however it may provide data that has to be forwarded to the other end.
pub enum Step {
    Done(Option<usize>),
    NeedsMore(Option<usize>),
}
// FIXME: This is wrong. There are three outcomes: Authentication Successfully ended, Auth is
//  still in progress, authentication errored.
//  *Completely* independent of that a mech may return data, even in the case of an error.
//  *On top of that* a mechanism may error for non-authentication related errors, e.g. IO errors
//  or missing properties in which case a mechanism has not written *valid* data and the
//  connection, if any, should be reset.
pub type StepResult = Result<Step, SessionError>;

impl SessionData {
    pub(crate) fn new(
        callback: Option<Arc<dyn Callback>>,
        global_properties: Arc<HashMap<Property, Arc<dyn Any + Send + Sync>>>,
        mechanism: &'static Mechanism,
        side: Side,
    ) -> Self {
        Self {
            callback,
            property_cache: HashMap::new(),
            global_properties,
            mechanism,
            side,
            channel_binding_data: None,
        }
    }
}

impl SessionData {
    pub fn callback<P: PropertyQ>(&mut self) -> Result<(), SessionError> {
        let property = P::property();
        self.callback_property(property)
    }

    pub fn validate(&mut self, validation: Validation) -> Result<(), SessionError> {
        self.callback
            .clone()
            .map(|cb| cb.validate(self, validation, self.mechanism.mechanism))
            .unwrap_or(Err(SessionError::no_validate(validation)))
    }

    pub fn get_property_or_callback<P: PropertyQ>(
        &mut self,
    ) -> Result<Option<Arc<P::Item>>, SessionError> {
        if !self.has_property::<P>() {
            match self.callback::<P>() {
                Ok(()) => {}
                Err(SessionError::NoCallback { .. }) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        Ok(self.get_property::<P>())
    }

    pub fn has_property<P: PropertyQ>(&self) -> bool {
        self.property_cache.contains_key(&P::property())
    }

    pub fn get_property<P: PropertyQ>(&self) -> Option<Arc<P::Item>> {
        self.property_cache
            .get(&P::property())
            .or_else(|| self.global_properties.get(&P::property()))
            .and_then(|prop| prop.clone().downcast::<P::Item>().ok())
    }

    pub fn set_property<P: PropertyQ>(
        &mut self,
        item: Arc<P::Item>,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        self.property_cache.insert(P::property(), item)
    }

    pub(crate) unsafe fn set_property_raw(&mut self, prop: Gsasl_property, data: Arc<String>) {
        let property = property_from_code(prop).unwrap();
        self.property_cache.insert(property, data);
    }

    pub(crate) fn callback_raw(&mut self, prop: Gsasl_property) -> Result<(), SessionError> {
        let property = property_from_code(prop).unwrap();
        self.callback_property(property)
    }

    pub(crate) fn callback_property(&mut self, property: Property) -> Result<(), SessionError> {
        self.callback
            .clone()
            .map(|cb| cb.provide_prop(self, property))
            .unwrap_or(Err(SessionError::NoCallback { property }))
    }

    pub(crate) fn set_channel_binding_data(&mut self, name: &'static str, value: Box<[u8]>) {
        self.channel_binding_data.replace((name, value));
    }

    pub(crate) fn get_cb_data(&self) -> Option<(&'static str, &[u8])> {
        self.channel_binding_data
            .as_ref()
            .map(|(name, value)| (*name, value.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gsasl::consts::{GSASL_AUTHID, GSASL_PASSWORD};
    use crate::mechanisms::plain::mechinfo::PLAIN;
    use crate::property::{AuthId, Password};
    use crate::{Mechname, Property, SASL};

    #[test]
    fn callback_test() {
        #[derive(Debug)]
        struct CB {
            data: usize,
        }
        impl Callback for CB {
            fn provide_prop(
                &self,
                session: &mut SessionData,
                _action: Property,
            ) -> Result<(), SessionError> {
                let _ = session.set_property::<AuthId>(Arc::new(format!("is {}", self.data)));
                Ok(())
            }
        }

        let cbox = CB { data: 0 };
        let mut session = SessionData::new(
            Some(Arc::new(cbox)),
            Arc::new(HashMap::new()),
            &PLAIN,
            Side::Client,
        );

        assert!(session.get_property::<AuthId>().is_none());
        assert_eq!(
            session
                .get_property_or_callback::<AuthId>()
                .unwrap()
                .unwrap()
                .as_str(),
            "is 0"
        );
    }

    #[test]
    fn property_set_get() {
        let sasl = SASL::new();
        let mut sess = sasl.client_start(Mechname::new(b"PLAIN").unwrap()).unwrap();

        assert!(sess.get_property::<AuthId>().is_none());
        assert!(sess.session_data.property_cache.is_empty());

        assert!(sess
            .set_property::<AuthId>(Arc::new("test".to_string()))
            .is_none());
        assert!(sess
            .set_property::<Password>(Arc::new("secret".to_string()))
            .is_none());

        assert_eq!(sess.get_property::<AuthId>().unwrap().as_str(), "test");
        assert_eq!(sess.get_property::<Password>().unwrap().as_str(), "secret");
        println!("{:?}", sess.session_data.property_cache);
    }

    #[test]
    fn property_set_raw() {
        let sasl = SASL::new();
        let mut sess = sasl.client_start(Mechname::new(b"PLAIN").unwrap()).unwrap();

        assert!(sess.get_property::<AuthId>().is_none());
        assert!(sess.session_data.property_cache.is_empty());

        unsafe {
            sess.session_data
                .set_property_raw(GSASL_AUTHID, Arc::new("test".to_string()));
            sess.session_data
                .set_property_raw(GSASL_PASSWORD, Arc::new("secret".to_string()));
        }

        assert_eq!(sess.get_property::<AuthId>().unwrap().as_str(), "test");
        assert_eq!(sess.get_property::<Password>().unwrap().as_str(), "secret");
    }
}
