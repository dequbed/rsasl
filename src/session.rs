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

#[allow(clippy::exhaustive_enums)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}

#[cfg(any(feature = "provider", feature = "testutils", test))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "provider", feature = "testutils"))))]
mod provider {
    use super::{
        ChannelBindingCallback, Mechanism, MechanismData, SessionCallback, SessionData,
        SessionError, Side, State, Validate,
    };
    use crate::alloc::boxed::Box;
    use crate::channel_bindings::NoChannelBindings;
    use crate::mechanism::Authentication;
    use crate::mechname::Mechname;
    use crate::sasl::Sasl;
    use crate::validate::{NoValidation, Validation};
    use acid_io::Write;

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
        pub const fn get_mechname(&self) -> &Mechname {
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
        /// A mechanism may exhibit undefined behaviour if `step` is called after either an Error
        /// or `State::Finished` has been returned by a previous call.  This includes behaviours
        /// such as writing garbage data to the provided writer, panicking, or blocking
        /// indefinitely.  It is thus paramount to construct a fresh `Session` if authentication is
        /// re-attempted after either `State::Finished` or an Error is returned.
        ///
        /// SASL itself can usually not tell you if an authentication was successful or not,
        /// instead this is done by the protocol itself.
        ///
        /// If the current side is going first, generate the first batch of data by calling this
        /// method with an input of `None`. Whether or not the current side is expected to go
        /// first can be checked with [`Session::are_we_first`].
        ///
        /// Not all protocols support both client-first and server-first Mechanisms, i.e. mechanisms in
        /// which the client sends the first batch of data and mechanisms in which the server sends
        /// the first batch of data. Refer to the documentation of the protocol in question on how to
        /// indicate to the other party that they have to provide the first batch of data.
        ///
        /// Data generated by a mechanism **MUST** be sent even if `step` returned
        /// `State::Finished`. This means that when `Ok(State::Finished(MessageSent::Yes)` is
        /// returned from `step` a final response **MUST** be sent to the other side to finish the
        /// authentication. This is true even no bytes were written into the provided writer. In
        /// that case a final empty response must be sent to the other party.
        pub fn step(
            &mut self,
            input: Option<&[u8]>,
            writer: &mut impl Write,
        ) -> Result<State, SessionError> {
            let state = {
                let validate = Validate::new::<V>(&mut self.sasl.validation);
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

            Ok(state)
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

        /// Returns `true` if a security layer is installed at the moment, otherwise returns `false`.
        pub fn has_security_layer(&self) -> bool {
            self.mechanism.has_security_layer()
        }

        /// Encode given data for an established SASL security layer
        ///
        /// This operation is also often called `wrap`. If a security layer has been established this
        /// method protects input data using said security layer and writes it into the provided writer.
        ///
        /// If no security layer has been installed this method returns
        /// `Err(`[`SessionError::NoSecurityLayer`]`).
        ///
        /// A call to this function returns the number of input bytes that were successfully
        /// protected and written into the given writer. As this protection may add overhead, use
        /// compression, etc. the number of bytes *written** will differ from the returned **read**
        /// amount of bytes. If a caller requires the number of bytes written it is their obligation to use
        /// a tracking writer.
        ///
        /// This method will not flush the provided writer.
        pub fn encode(
            &mut self,
            input: &[u8],
            writer: &mut impl Write,
        ) -> Result<usize, SessionError> {
            self.mechanism.encode(input, writer)
        }

        /// Decode data from an established SASL security layer
        ///
        /// This operation is also often called `unwrap`. If a security layer has been established this
        /// method unprotects input data from said security layer and writes it into the provided
        /// writer.
        ///
        /// If no security layer has been installed this method returns
        /// `Err(`[`SessionError::NoSecurityLayer`]`)`.
        ///
        /// A call to this function returns the number of protected input bytes that were successfully
        /// unprotected and written into the given writer. Similar to [`Self::encode`] the number of
        /// bytes read from input may differ from the amount of output bytes written into the
        /// writer.
        ///
        /// This method will not flush the provided writer.
        pub fn decode(
            &mut self,
            input: &[u8],
            writer: &mut impl Write,
        ) -> Result<usize, SessionError> {
            self.mechanism.decode(input, writer)
        }
    }

    #[cfg(feature = "provider_base64")]
    #[cfg_attr(docsrs, doc(cfg(feature = "provider_base64")))]
    impl<V: Validation, C: ChannelBindingCallback> Session<V, C> {
        /// Perform one step of SASL authentication, base64 encoded.
        ///
        /// *requires feature `provider_base64`*
        ///
        /// This is a utility function wrapping [`Session::step`] to consume and produce
        /// base64-encoded data. See the documentation of `step` for details on how this function
        /// operates and how to handle the different returned values.
        ///
        /// Requiring base64-encoded SASL data is common in line-based or textual formats, such as
        /// SMTP, IMAP, XMPP and IRCv3.
        /// Refer to your protocol documentation if SASL data needs to be base64 encoded.
        pub fn step64(
            &mut self,
            input: Option<&[u8]>,
            writer: &mut impl Write,
        ) -> Result<State, SessionError> {
            use base64::write::EncoderWriter;
            let mut writer64 = EncoderWriter::new(writer, base64::STANDARD);

            let state = if let Some(input) = input {
                let input = base64::decode_config(input, base64::STANDARD)?;
                self.step(Some(&input[..]), &mut writer64)
            } else {
                self.step(None, &mut writer64)
            }?;
            Ok(state)
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
        pub(crate) const fn new(mechanism_desc: Mechanism, side: Side) -> Self {
            Self {
                mechanism_desc,
                side,
            }
        }
    }

    #[cfg(test)]
    pub mod tests {
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
                let mut mechanism_data = MechanismData::new(
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
#[cfg_attr(docsrs, doc(cfg(any(feature = "provider", feature = "testutils"))))]
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
        &mut self,
        provider: &dyn Provider,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        let context = build_context(provider);
        match self.callback.callback(&self.session_data, context, request) {
            Ok(()) | Err(SessionError::CallbackError(CallbackError::EarlyReturn(_))) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn action<'a, T>(
        &mut self,
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

    pub fn need_with<P, F, G>(
        &mut self,
        provider: &dyn Provider,
        closure: F,
    ) -> Result<G, SessionError>
    where
        P: for<'p> Property<'p>,
        F: FnOnce(&<P as Property<'_>>::Value) -> Result<G, SessionError>,
    {
        self.maybe_need_with::<P, F, G>(provider, closure)?
            .ok_or_else(|| CallbackError::NoCallback(type_name::<P>()).into())
    }

    pub fn maybe_need_with<P, F, G>(
        &mut self,
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
            // explicitly ignore a `NoValue` error since that one *is actually okay*
            Ok(()) | Err(SessionError::CallbackError(CallbackError::NoValue)) => Ok(()),
            Err(error) => Err(error),
        }?;
        Ok(closurecr.try_unwrap())
    }

    pub fn maybe_need_cb_data<'a, P, F, G>(
        &mut self,
        cbname: &'a str,
        provider: P,
        f: F,
    ) -> Result<Option<G>, SessionError>
    where
        P: Provider<'a>,
        F: FnOnce(&[u8]) -> Result<G, SessionError>,
    {
        let prov = ThisProvider::<ChannelBindingName>::with(cbname).and(provider);
        if let Some(cbdata) = self.chanbind_cb.get_cb_data(cbname) {
            f(cbdata).map(Some)
        } else {
            self.maybe_need_with::<ChannelBindings, F, G>(&prov, f)
        }
    }

    pub fn need_cb_data<'a, P, F, G>(
        &mut self,
        cbname: &'a str,
        provider: P,
        f: F,
    ) -> Result<G, SessionError>
    where
        P: Provider<'a>,
        F: FnOnce(&[u8]) -> Result<G, SessionError>,
    {
        self.maybe_need_cb_data(cbname, provider, f)?
            .ok_or_else(|| SessionError::MissingChannelBindingData(cbname.to_string()))
    }
}

impl fmt::Debug for MechanismData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MechanismData").finish()
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
    #[must_use]
    pub const fn mechanism(&self) -> &Mechanism {
        &self.mechanism_desc
    }

    #[must_use]
    pub const fn side(&self) -> Side {
        self.side
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums)]
/// State result of the underlying Mechanism implementation
pub enum State {
    /// The Mechanism has not yet completed the authentication exchange
    ///
    /// If this is returned the mechanism has written a message to be sent to the other
    /// party into the provided writer and is expecting a response.
    Running,

    /// The Mechanism has received all required information from the other party.
    ///
    /// However, a Mechanism returning `Finished` may still have *written* data. This data MUST be
    /// sent to the other party to ensure both sides have received all required data. The fact if
    /// a message is to be sent is indicated by the contained [`MessageSent`].
    ///
    /// After a `Finished` is returned `step` or `step64` MUST NOT be called further.
    ///
    /// **NOTE**: This state does not guarantee that the authentication was *successful*, only that
    /// no further calls to `step` or `step64` are possible.
    /// Most SASL mechanisms have no way of returning the authentication outcome inline.
    /// Instead the outer protocol will indicate the authentication outcome in a protocol-specific
    /// way.
    Finished(MessageSent),
}
impl State {
    #[inline(always)]
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    #[inline(always)]
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        !self.is_running()
    }

    #[inline(always)]
    #[must_use]
    pub const fn has_sent_message(&self) -> bool {
        matches!(self, Self::Running | Self::Finished(MessageSent::Yes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums)]
/// Indication if a message was written into the provided writer.
///
/// This enum is returned by a call to `step` or `step64` and indicates if a message was written
/// into the provided writer. It serves as a hint to a caller to inform them that they need to
/// ensure the message will reach the other party, be that by flushing the writer or copying the
/// written bytes.
///
/// Note that SASL explicitly allows the option of sending an *empty* message. In that case a
/// `MessageSent::Yes` will be returned but no bytes will have been written into the writer. How
/// to indicate an empty message differs from protocol to protocol.
pub enum MessageSent {
    /// Yes a message was written and needs to be sent
    Yes,
    /// No message needs to be sent to the other end.
    No,
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_impl_all!(Session: Send, Sync);
}
