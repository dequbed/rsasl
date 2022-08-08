use core::any::type_name;
use core::fmt;

use crate::callback::{Action, CallbackError, ClosureCR, Request, Satisfy, SessionCallback};
use crate::channel_bindings::ChannelBindingCallback;
use crate::context::{build_context, Provider, ProviderExt, ThisProvider};
use crate::error::SessionError;
use crate::property::{ChannelBindingName, ChannelBindings, Property};
use crate::registry::Mechanism;
use crate::typed::{tags, Tagged};
use crate::validate::{Validate, ValidationError};

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}

#[cfg(any(feature = "provider", feature = "testutils", test))]
mod provider {
    use super::*;
    use crate::channel_bindings::NoChannelBindings;
    use crate::mechanism::Authentication;
    use crate::mechname::Mechname;
    use crate::sasl::Sasl;
    use crate::validate::{NoValidation, Validation};
    use std::io::Write;

    /// This represents a single authentication exchange
    ///
    /// An authentication exchange may have multiple steps, with each step potentially sending data
    /// to the other party and/or receiving data from the other party.
    ///
    /// On a server-side session after a `Finished` is received validation data from the user
    /// callback may be extracted with a call to [`Session::validation`].
    pub struct Session<V: Validation = NoValidation, C = NoChannelBindings> {
        sasl: Sasl<V, C>,
        side: Side,
        mechanism: Box<dyn Authentication>,
        mechanism_desc: Mechanism,
    }

    impl<V: Validation, C: ChannelBindingCallback> Session<V, C> {
        pub(crate) fn new(
            sasl: Sasl<V, C>,
            side: Side,
            mechanism: Box<dyn Authentication>,
            mechanism_desc: Mechanism,
        ) -> Self {
            Self {
                sasl,
                side,
                mechanism,
                mechanism_desc,
            }
        }

        #[inline(always)]
        /// Return `true` if this side of the authentication exchange should go first.
        ///
        /// Mechanisms in SASL may be either "server-first" or "client-first" indicating which side
        /// needs to send the first message in an authentication exchange.
        ///
        /// For example:
        /// `PLAIN` is a client-first mechanism. The client sends the first message, containing the
        /// username and password in plain text. `DIGEST-MD5` on the other hand is server-first, an
        /// authentication begins with a server sending a 'challenge' to the client.
        ///
        /// This method returns if the current side must go first, i.e. if this method returns `true`
        /// then `step` or `step64` must be called with no input data to begin the authentication. If
        /// this method returns `false` then the first call to `step` or `step64` can only be
        /// performed after input data was received from the other party.
        pub fn are_we_first(&self) -> bool {
            self.side == self.mechanism_desc.first
        }

        /// Return the name of the mechanism in use
        pub fn get_mechname(&self) -> &Mechname {
            self.mechanism_desc.mechanism
        }

        /// Perform one step of SASL authentication.
        ///
        /// *requires feature `provider`*
        ///
        /// A protocol implementation calls this method with data provided by the other party,
        /// returning response data written to the other party until after a [`State::Finished`] is
        /// returned.
        ///  **Note:** If the other side indicates a completed authentication and sends no further
        /// authentication data but the last call to `step` returned `State::Running` you **MUST**
        /// call `step` a final time with a `None` input!
        /// This is critical to upholding all security guarantees that different mechanisms offer.
        ///
        /// SASL itself can usually not tell you if an authentication was successful or not,
        /// instead this is done by the protocol itself.
        ///
        /// If the current side is going first, generate the first batch of data by calling this
        /// method with an input of `None`.
        ///
        /// Not all protocols support both client-first and server-first Mechanisms, i.e. mechanisms in
        /// which the client sends the first batch of data and mechanisms in which the server sends
        /// the first batch of data. Refer to the documentation of the protocol in question on how to
        /// indicate to the other party that they have to provide the first batch of data.
        ///
        /// Keep in mind that SASL makes a distinction between zero-sized data to send and no data to
        /// send. In the former case the second element of the return tuple is `Some(0)`, in the
        /// latter case it is `None`.
        /// This data **MUST** be sent even if `step` returned `State::Finished`. This means that
        /// e.g. when `Ok((State::Finished, Some(0)))` is returned from step a final empty
        /// response **MUST** be sent to the other side to finish the authentication.
        /// Only if a `None` is returned in the tuple no message needs to be sent.
        pub fn step(
            &mut self,
            input: Option<&[u8]>,
            writer: &mut impl Write,
        ) -> Result<(State, Option<usize>), SessionError> {
            let mut tagged_option = Tagged::<'_, V>(None);

            let (state, written) = {
                let validate = Validate::new::<V>(&mut tagged_option);
                let mut mechanism_data = MechanismData::new(
                    self.sasl.config.get_callback(),
                    &self.sasl.cb,
                    validate,
                    self.mechanism_desc,
                    self.side,
                );
                if let Some(input) = input {
                    self.mechanism
                        .step(&mut mechanism_data, Some(input), writer)
                } else {
                    self.mechanism.step(&mut mechanism_data, None, writer)
                }?
            };

            if state == State::Finished {
                self.sasl.validation = tagged_option.0.take();
            }

            Ok((state, written))
        }

        /// Extract the [`Validation`] result of an authentication exchange
        ///
        /// This are useful to e.g. indicate success or failure of the authentication exchange and
        /// supply the protocol crate with information about the user that was authenticated.
        ///
        /// Validation results are generated by the user-supplied callback. They thus allow to send
        /// information from the callback to the protocol implementation. The type of this information
        /// can be freely defined by said implementation, but due to required type erasure inside rsasl
        /// the type must be exposed to the downstream user. Further details regarding this mechanic
        /// can be found in the [`validate`](crate::validate) module documentation.
        ///
        /// This method will most likely return `None` until `step` has returned with
        /// `State::Finished`, but it not guaranteed to do so.
        pub fn validation(&mut self) -> Option<V::Value> {
            self.sasl.validation.take()
        }
    }

    #[cfg(feature = "provider_base64")]
    impl<V: Validation, C: ChannelBindingCallback> Session<V, C> {
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
            input: Option<&[u8]>,
            writer: &mut impl Write,
        ) -> Result<(State, Option<usize>), SessionError> {
            use base64::write::EncoderWriter;
            let mut writer64 = EncoderWriter::new(writer, base64::STANDARD);

            if let Some(input) = input {
                let input = base64::decode_config(input, base64::STANDARD)?;
                self.step(Some(&input[..]), &mut writer64)
            } else {
                self.step(None, &mut writer64)
            }
        }
    }

    impl<'a> MechanismData<'a> {
        fn new(
            callback: &'a dyn SessionCallback,
            chanbind_cb: &'a dyn ChannelBindingCallback,
            validator: &'a mut Validate<'a>,
            mechanism_desc: Mechanism,
            side: Side,
        ) -> Self {
            Self {
                callback,
                chanbind_cb,
                validator,
                session_data: SessionData::new(mechanism_desc, side),
            }
        }
    }

    impl SessionData {
        pub(crate) fn new(mechanism_desc: Mechanism, side: Side) -> Self {
            Self {
                mechanism_desc,
                side,
            }
        }
    }

    #[cfg(test)]
    pub(crate) mod tests {
        use super::*;
        use crate::context::EmptyProvider;
        use crate::validate::Validation;

        impl<V: Validation, CB: ChannelBindingCallback> Session<V, CB> {
            pub fn get_cb_data<'a, F, G>(
                &'a self,
                cbname: &str,
                validate: &'a mut Validate<'a>,
                f: &mut F,
            ) -> Result<G, SessionError>
            where
                F: FnMut(&[u8]) -> Result<G, SessionError>,
            {
                let mechanism_data = MechanismData::new(
                    self.sasl.config.get_callback(),
                    &self.sasl.cb,
                    validate,
                    self.mechanism_desc,
                    self.side,
                );
                mechanism_data.need_cb_data(cbname, EmptyProvider, f)
            }
        }
    }
}
#[cfg(any(feature = "provider", feature = "testutils", test))]
pub use provider::Session;

pub struct MechanismData<'a> {
    callback: &'a dyn SessionCallback,
    chanbind_cb: &'a dyn ChannelBindingCallback,
    validator: &'a mut Validate<'a>,
    session_data: SessionData,
}

impl MechanismData<'_> {
    pub fn validate(&mut self, provider: &dyn Provider) -> Result<(), ValidationError> {
        let context = build_context(provider);
        self.callback
            .validate(&self.session_data, context, self.validator)
    }

    fn callback(
        &self,
        provider: &dyn Provider,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        let context = build_context(provider);
        match self.callback.callback(&self.session_data, context, request) {
            Ok(()) => Ok(()),
            Err(SessionError::CallbackError(CallbackError::EarlyReturn(_))) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn action<'a, T>(
        &self,
        provider: &dyn Provider,
        value: &'a T::Value,
    ) -> Result<(), SessionError>
    where
        T: Property<'a>,
    {
        let mut tagged = Tagged::<'a, Action<T>>(Some(value));
        self.callback(provider, Request::new_action::<T>(&mut tagged))?;
        if tagged.is_some() {
            Err(SessionError::CallbackError(CallbackError::NoCallback(
                type_name::<T>(),
            )))
        } else {
            Ok(())
        }
    }

    pub fn need_with<P, F, G>(&self, provider: &dyn Provider, closure: F) -> Result<G, SessionError>
    where
        P: for<'p> Property<'p>,
        F: FnOnce(&<P as Property<'_>>::Value) -> Result<G, SessionError>,
    {
        self.maybe_need_with::<P, F, G>(provider, closure)?
            .ok_or_else(|| CallbackError::NoCallback(type_name::<P>()).into())
    }

    pub fn maybe_need_with<P, F, G>(
        &self,
        provider: &dyn Provider,
        closure: F,
    ) -> Result<Option<G>, SessionError>
    where
        P: for<'p> Property<'p>,
        F: FnOnce(&<P as Property<'_>>::Value) -> Result<G, SessionError>,
    {
        let mut closurecr = ClosureCR::<P, _, _>::wrap(closure);
        let mut tagged = Tagged::<'_, tags::RefMut<Satisfy<P>>>(&mut closurecr);
        match self.callback(provider, Request::new_satisfy::<P>(&mut tagged)) {
            Ok(()) => Ok(()),
            // explicitly ignore a `NoValue` error since that one *is actually okay*
            Err(SessionError::CallbackError(CallbackError::NoValue)) => Ok(()),
            Err(error) => Err(error),
        }?;
        Ok(closurecr.try_unwrap())
    }

    pub fn need_cb_data<'a, P, F, G>(
        &self,
        cbname: &'a str,
        provider: P,
        f: F,
    ) -> Result<G, SessionError>
    where
        P: Provider<'a>,
        F: FnOnce(&[u8]) -> Result<G, SessionError>,
    {
        let prov = ThisProvider::<ChannelBindingName>::with(cbname).and(provider);
        if let Some(cbdata) = self.chanbind_cb.get_cb_data(cbname) {
            f(cbdata)
        } else {
            self.maybe_need_with::<ChannelBindings, F, G>(&prov, f)?
                .ok_or_else(|| SessionError::MissingChannelBindingData(cbname.to_string()))
        }
    }
}

#[derive(Debug)]
// TODO: Since the Session object is only known to the protocol implementation and user they can
//       share a statically known Context.
pub struct SessionData {
    mechanism_desc: Mechanism,
    side: Side,
}
impl SessionData {
    pub fn mechanism(&self) -> &Mechanism {
        &self.mechanism_desc
    }

    pub fn side(&self) -> Side {
        self.side
    }
}

impl fmt::Debug for MechanismData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionData").finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// State result of the underlying Mechanism implementation
pub enum State {
    /// The Mechanism has not yet completed the authentication exchange
    Running,

    /// The Mechanism has received all required information from the other party.
    ///
    /// However, a Mechanism returning `Finished` may still have *written* data. This data MUST be
    /// sent to the other party to ensure both sides have received all required data.
    ///
    /// After a `Finished` is returned `step` or `step64` MUST NOT be called further.
    ///
    /// **NOTE**: This state does not guarantee that the authentication was *successful*, only that
    /// no further calls to `step` or `step64` are possible.
    /// Most SASL mechanisms have no way of returning the authentication outcome inline.
    /// Instead the outer protocol will indicate the authentication outcome in a protocol-specific
    /// way.
    Finished,
}
impl State {
    #[inline(always)]
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }
    #[inline(always)]
    pub fn is_finished(&self) -> bool {
        !self.is_running()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_autoimpl() {
        static_assertions::assert_impl_all!(Session: Send, Sync);
        assert!(true)
    }
}
