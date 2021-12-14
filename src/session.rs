use std::any::{Any, TypeId};
use std::collections::HashMap;

use crate::{Callback, Mechanism, RsaslError};
use crate::consts::{GSASL_NO_CALLBACK, Property};

pub struct AuthSession<'session> {
    mechanism: Box<dyn Mechanism>,
    session_data: Session<'session>,
}

impl<'session> AuthSession<'session> {
    pub(crate) fn new<'sasl: 'session>(sasl: Option<&'sasl dyn Callback>,
                                       mechanism: Box<dyn Mechanism>
    ) -> Self
    {
        Self {
            mechanism,
            session_data: Session::new(sasl),
        }
    }
}

impl AuthSession<'_> {
    /// Perform one step of SASL authentication. This reads data from `input` then processes it,
    /// potentially calling a configured callback for required properties or enact decisions, and
    /// finally returns data to be send to the other party.
    pub fn step(&mut self, input: Option<&[u8]>) -> StepResult {
        self.mechanism.step(&mut self.session_data, input)
    }
}


#[derive(Debug)]
pub struct Session<'session> {
    callback: Option<&'session dyn Callback>,
    map: HashMap<TypeId, Box<dyn Any>>,
}

#[derive(Debug)]
/// The outcome of a single step in the authentication exchange
///
/// Since SASL is multi-step each step can either complete the exchange or require more steps to be
/// performed. In both cases however it may provide data that has to be forwarded to the other end.
pub enum Step {
    Done(Option<Box<[u8]>>),
    NeedsMore(Option<Box<[u8]>>),
}
pub type StepResult = Result<Step, RsaslError>;

impl<'session> Session<'session> {
    pub(crate) fn new(callback: Option<&'session dyn Callback>) -> Self {
        Self {
            callback,
            map: HashMap::new(),
        }
    }
}

impl Session<'_> {
    pub fn callback(&mut self) -> Result<(), RsaslError> {
        if let Some(cb) = self.callback {
            cb.callback(self)
        } else {
            Err(GSASL_NO_CALLBACK)
        }
    }

    pub fn get_property_or_callback<P: Property>(&mut self) -> Option<P::Item> {
        if let Some(item) = self.get_property::<P>() {
            Some(item)
        } else {
            let _ = self.callback();
            self.get_property::<P>()
        }
    }

    pub fn get_property<P: Property>(&self) -> Option<P::Item> {
        self.map.get(&TypeId::of::<P::Item>()).and_then(|prop| {
            prop.downcast_ref::<P::Item>()
                .map(|prop| (*prop).clone())
        })
    }

    pub fn set_property<P: Property>(&mut self, item: Box<P::Item>) -> Option<Box<dyn Any>> {
        self.map.insert(TypeId::of::<P::Item>(), item)
    }
}

#[cfg(test)]
mod tests {
    use crate::consts::AUTHID;
    use super::*;

    #[test]
    fn callback_test() {
        #[derive(Debug)]
        struct CB {
            data: usize,
        }
        impl Callback for CB {
            fn callback(&self, session: &mut Session) -> Result<(), RsaslError> {
                let _ = session.set_property::<AUTHID>(Box::new(format!("is {}", self.data)));

                Ok(())
            }
        }

        let cbox = CB { data: 0 };
        let mut session = Session::new(Some(&cbox));

        assert!(session.get_property::<AUTHID>().is_none());
        assert_eq!(session.get_property_or_callback::<AUTHID>(), Some("is 0".to_string()))
    }
}