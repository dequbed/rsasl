use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::sync::Arc;
use base64::write::EncoderWriter;

use crate::{Callback, Mechname, Property, SASLError};
use crate::channel_binding::NoChannelBindings;
use crate::gsasl::consts::{Gsasl_property, property_from_code};
use crate::mechanism::Authentication;
use crate::property::PropertyQ;
use crate::validate::*;

pub struct Session {
    mechanism: Box<dyn Authentication>,
    session_data: SessionData,
}

impl Session {
    pub(crate) fn new(
        callback: Option<Arc<dyn Callback>>,
        global_properties: Arc<HashMap<Property, Box<dyn Any>>>,
        mechname: &'static Mechname,
        mechanism: Box<dyn Authentication>,
    ) -> Self
    {
        Self {
            mechanism,
            session_data: SessionData::new(callback, global_properties, mechname),
        }
    }

    pub fn set_property<P: PropertyQ>(&mut self, item: Box<P::Item>) -> Option<Box<P::Item>> {
        self.session_data.set_property::<P>(item)
            .map(|old| old.downcast().expect("old session data value was of bad type"))
    }

    pub fn get_property<P: PropertyQ>(&mut self) -> Result<&P::Item, SASLError> {
        self.session_data.get_property::<P>()
    }

    pub fn get_mechanism(&self) -> &'static Mechname {
        self.session_data.mechname
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
            self.mechanism.step(&mut self.session_data, Some(input.as_ref()), writer)
        } else {
            self.mechanism.step(&mut self.session_data, None, writer)
        }
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
    pub fn step64(&mut self, input: Option<impl AsRef<[u8]>>, writer: &mut impl Write) -> StepResult {
        let input = input
            .map(|inp| base64::decode_config(inp.as_ref(), base64::STANDARD))
            .transpose()?;
        let mut writer64 = EncoderWriter::new(writer, base64::STANDARD);
        self.step(input, &mut writer64)
    }
}

pub struct SessionData {
    pub(crate) callback: Option<Arc<dyn Callback>>,
    property_cache: HashMap<Property, Box<dyn Any>>,
    global_properties: Arc<HashMap<Property, Box<dyn Any>>>,
    mechname: &'static Mechname,
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
pub type StepResult = Result<Step, SASLError>;

impl SessionData {
    pub(crate) fn new(
        callback: Option<Arc<dyn Callback>>,
        global_properties: Arc<HashMap<Property, Box<dyn Any>>>,
        mechname: &'static Mechname
    ) -> Self {
        Self {
            callback,
            property_cache: HashMap::new(),
            global_properties,
            mechname,
        }
    }
}

impl SessionData {
    pub fn callback<P: PropertyQ>(&mut self) -> Result<(), SASLError> {
        let property = P::property();
        self.callback_property(property)
    }

    pub fn validate(&mut self, validation: Validation) -> Result<(), SASLError> {
        self.callback.clone()
            .map(|cb| cb.validate(self, validation, self.mechname))
            .unwrap_or(Err(SASLError::NoValidate { validation }))
    }

    pub fn get_property_or_callback<P: PropertyQ>(&mut self) -> Result<&P::Item, SASLError> {
        if !self.has_property::<P>() {
            let _ = self.callback::<P>()?;
        }
        self.get_property::<P>()
    }

    pub fn has_property<P: PropertyQ>(&self) -> bool {
        self.property_cache.contains_key(&P::property())
    }

    pub fn get_property<P: PropertyQ>(&self) -> Result<&P::Item, SASLError> {
        self.property_cache.get(&P::property())
            .or_else(|| self.global_properties.get(&P::property()))
            .and_then(|prop| prop.downcast_ref::<P::Item>())
            .ok_or(SASLError::no_property::<P>())
    }

    pub fn set_property<P: PropertyQ>(&mut self, item: Box<P::Item>) -> Option<Box<dyn Any>> {
        self.property_cache.insert(P::property(), item)
    }

    pub(crate) unsafe fn set_property_raw(&mut self, prop: Gsasl_property, data: Box<String>) {
        let property = property_from_code(prop).unwrap();
        self.property_cache.insert(property, data);
    }

    pub(crate) fn callback_raw(&mut self, prop: Gsasl_property) -> Result<(), SASLError> {
        let property = property_from_code(prop).unwrap();
        self.callback_property(property)
    }

    pub(crate) fn callback_property(&mut self, property: Property) -> Result<(), SASLError> {
        self.callback.clone()
            .map(|cb| cb.provide_prop(self, property))
            .unwrap_or(Err(SASLError::NoCallback { property }))
    }
}

#[cfg(test)]
mod tests {
    use crate::{Mechname, Property, SASL};
    use crate::gsasl::consts::{GSASL_AUTHID, GSASL_PASSWORD};
    use crate::property::{AuthId, AUTHID, Password, PASSWORD};
    use super::*;

    #[test]
    fn callback_test() {
        #[derive(Debug)]
        struct CB {
            data: usize,
        }
        impl Callback for CB {
            fn provide_prop(&self, session: &mut SessionData, _action: Property) ->
            Result<(), SASLError> {
                let _ = session.set_property::<AuthId>(Box::new(format!("is {}", self.data)));
                Ok(())
            }
        }

        let cbox = CB { data: 0 };
        let mechname = Mechname::new_unchecked("X-TEST");
        let mut session = SessionData::new(
            Some(Arc::new(cbox)),
            Arc::new(HashMap::new()),
                mechname,
        );

        assert!(session.get_property::<AuthId>().is_err());
        assert_eq!(session.get_property_or_callback::<AuthId>().unwrap(), "is 0");
    }

    #[test]
    fn property_set_get() {
        let sasl = SASL::new();
        let mut sess = sasl.client_start(Mechname::new(b"PLAIN").unwrap())
            .unwrap();

        assert!(sess.get_property::<AuthId>().is_err());
        assert!(sess.session_data.property_cache.is_empty());

        assert!(sess.set_property::<AuthId>(Box::new("test".to_string())).is_none());
        assert!(sess.set_property::<Password>(Box::new("secret".to_string())).is_none());

        assert_eq!(sess.get_property::<AuthId>().unwrap(), "test");
        assert_eq!(sess.get_property::<Password>().unwrap(), "secret");
        println!("{:?}", sess.session_data.property_cache);
    }

    #[test]
    fn property_set_raw() {
        let sasl = SASL::new();
        let mut sess = sasl.client_start(Mechname::new(b"PLAIN").unwrap()).unwrap();


        assert!(sess.get_property::<AuthId>().is_err());
        assert!(sess.session_data.property_cache.is_empty());

        unsafe {
            sess.session_data.set_property_raw(GSASL_AUTHID, Box::new("test".to_string()));
            sess.session_data.set_property_raw(GSASL_PASSWORD, Box::new("secret".to_string()));
        }

        assert_eq!(sess.get_property::<AuthId>().unwrap(), "test");
        assert_eq!(sess.get_property::<Password>().unwrap(), "secret");
    }

}