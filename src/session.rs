use std::any::Any;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use crate::{Callback, Mechanism, SaslError};
use crate::consts::{GSASL_NO_CALLBACK, Gsasl_property, Property};

pub struct Session {
    mechanism: Box<dyn Mechanism>,
    session_data: SessionData,
}

impl Session {
    pub(crate) fn new(callback: Option<Arc<Box<dyn Callback>>>,
                      mechanism: Box<dyn Mechanism>
    ) -> Self
    {
        Self {
            mechanism,
            session_data: SessionData::new(callback),
        }
    }

    /// Perform one step of SASL authentication. This reads data from `input` then processes it,
    /// potentially calling a configured callback for required properties or enact decisions, and
    /// finally returns data to be send to the other party.
    pub fn step(&mut self, input: Option<&[u8]>, writer: &mut impl Write) -> StepResult {
        self.mechanism.step(&mut self.session_data, input, writer)
    }

    pub fn set_property<P: Property>(&mut self, item: Box<P::Item>) -> Option<Box<dyn Any>> {
        self.session_data.set_property::<P>(item)
    }

    pub fn get_property<P: Property>(&mut self) -> Option<P::Item> {
        self.session_data.get_property::<P>()
    }
}


#[derive(Debug)]
pub struct SessionData {
    callback: Option<Arc<Box<dyn Callback>>>,
    map: HashMap<Gsasl_property, Box<dyn Any>>,
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
pub type StepResult = Result<Step, SaslError>;

impl SessionData {
    pub(crate) fn new(callback: Option<Arc<Box<dyn Callback>>>) -> Self {
        Self {
            callback,
            map: HashMap::new(),
        }
    }
}

impl SessionData {
    pub fn callback(&mut self, code: Gsasl_property) -> Result<(), SaslError> {
        if let Some(cb) = self.callback.clone() {
            cb.callback(self, code)
        } else {
            Err(GSASL_NO_CALLBACK.into())
        }
    }

    pub fn get_property_or_callback<P: Property>(&mut self) -> Option<P::Item> {
        if let Some(item) = self.get_property::<P>() {
            Some(item)
        } else {
            let _ = self.callback(P::code()).ok()?;
            self.get_property::<P>()
        }
    }

    pub fn get_property<P: Property>(&self) -> Option<P::Item> {
        self.map.get(&P::code()).and_then(|prop| {
            prop.downcast_ref::<P::Item>()
                .map(|prop| (*prop).clone())
        })
    }

    pub fn set_property<P: Property>(&mut self, item: Box<P::Item>) -> Option<Box<dyn Any>> {
        self.map.insert(P::code(), item)
    }

    pub(crate) unsafe fn set_property_raw(&mut self, prop: Gsasl_property, data: Box<String>) {
        let _ = self.map.insert(prop, data);
    }
}

#[cfg(test)]
mod tests {
    use crate::consts::{AUTHID, GSASL_AUTHID, GSASL_PASSWORD, PASSWORD};
    use crate::{SASL, Shared};
    use super::*;

    #[test]
    fn callback_test() {
        #[derive(Debug)]
        struct CB {
            data: usize,
        }
        impl Callback for CB {
            fn callback(&self, session: &mut SessionData, _code: Gsasl_property) -> Result<(), SaslError> {
                let _ = session.set_property::<AUTHID>(Box::new(format!("is {}", self.data)));

                Ok(())
            }
        }

        let cbox = CB { data: 0 };
        let mut session = SessionData::new(Some(Arc::new(Box::new(cbox))));

        assert!(session.get_property::<AUTHID>().is_none());
        assert_eq!(session.get_property_or_callback::<AUTHID>(), Some("is 0".to_string()))
    }

    #[test]
    fn property_set_get() {
        let sasl = SASL::new(Shared::new().unwrap());
        let mut sess = sasl.client_start("PLAIN")
            .unwrap();

        assert!(sess.get_property::<AUTHID>().is_none());
        assert!(sess.session_data.map.is_empty());

        assert!(sess.set_property::<AUTHID>(Box::new("test".to_string())).is_none());
        assert!(sess.set_property::<PASSWORD>(Box::new("secret".to_string())).is_none());

        assert_eq!(sess.get_property::<AUTHID>(), Some("test".to_string()));
        assert_eq!(sess.get_property::<PASSWORD>(), Some("secret".to_string()));
    }

    #[test]
    fn property_set_raw() {
        let sasl = SASL::new(Shared::new().unwrap());
        let mut sess = sasl.client_start("PLAIN").unwrap();


        assert!(sess.get_property::<AUTHID>().is_none());
        assert!(sess.session_data.map.is_empty());

        unsafe {
            sess.session_data.set_property_raw(GSASL_AUTHID, Box::new("test".to_string()));
            sess.session_data.set_property_raw(GSASL_PASSWORD, Box::new("secret".to_string()));
        }

        assert_eq!(sess.get_property::<AUTHID>(), Some("test".to_string()));
        assert_eq!(sess.get_property::<PASSWORD>(), Some("secret".to_string()));
    }
}