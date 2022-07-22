use std::fmt::{Debug, Formatter};
use std::io::Write;


use std::sync::Arc;

use crate::callback::{Action, CallbackError, CallbackRequest, ClosureCR, Request, Satisfy, SessionCallback};
use crate::channel_bindings::{ChannelBindingCallback, NoChannelBindings};
use crate::context::{build_context, Provider};
use crate::error::SessionError;
use crate::gsasl::consts::Gsasl_property;
use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use crate::property::{ChannelBindings, Property};
use crate::registry::Mechanism;
use crate::sasl::SASL;
use crate::typed::{tags, TaggedOption};
use crate::validate::{NoValidation, Validate, Validation, ValidationError};

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}

pub type ClientSession<CB = NoChannelBindings> = Session<NoValidation, CB>;
pub type ServerSession<V, CB = NoChannelBindings> = Session<V, CB>;

/// This represents a single authentication exchange
///
/// An authentication exchange may have multiple steps, with each step potentially sending data
/// to the other party and/or receiving data from the other party.
///
/// A step is performed using either the [`Session::step`] method, or — base64-wrapped — using
/// [`Session::step64`]. These methods will return [`State::Running`] if another call to `step`
/// is expected, or [`State::Finished`] when the exchange has concluded and no more calls to
/// `step` are necessary. After a `Finished` is received calling `step` again is undefined
/// behaviour. Mechanisms may write garbage data, hang forever or return an `Err`.
///
/// However, `Finished` only indicates that no further calls to `step`
/// are possible, mechanisms will have likely generated data that must still be forwarded to the
/// other party.
///
/// Similarly, a return of `Finished` does *not* indicate that the authentication was
/// **successful**, only that it was completed. SASL mechanisms usually have no provisions for
/// returning authentication results inline, meaning the outcome of the authentication is
/// indicated by the outer protocol using SASL in some protocol-specific way.
///
/// On a server-side session after a `Finished` is received validation data from the user
/// callback may be extracted with a call to [`Session::validation`].
pub struct Session<V: Validation, C> {
    sasl: SASL<V, C>,
    side: Side,
    mechanism: Box<dyn Authentication>,
    mechanism_desc: Mechanism,
}

#[cfg(feature = "provider")]
impl<V: Validation, C: ChannelBindingCallback> Session<V, C> {
    pub(crate) fn new(
        sasl: SASL<V, C>,
        side: Side,
        mechanism: Box<dyn Authentication>,
        mechanism_desc: Mechanism,
    ) -> Self {
        Self { sasl, side, mechanism, mechanism_desc }
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
    pub fn step(
        &mut self,
        input: Option<&[u8]>,
        writer: &mut impl Write,
    ) -> Result<(State, Option<usize>), SessionError> {
        let mut tagged_option = TaggedOption::<'_, V>(None);

        let (state, written) = {
            let validate = Validate::new::<V>(&mut tagged_option);
            let mut mechanism_data = MechanismData::new(
                self.sasl.config.callback.as_ref(),
                &self.sasl.cb,
                validate,
                self.mechanism_desc,
                self.side,
            );
            if let Some(input) = input {
                self.mechanism
                    .step(&mut mechanism_data, Some(input.as_ref()), writer)
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

pub struct MechanismData<'a> {
    callback: &'a dyn SessionCallback,
    chanbind_cb: &'a dyn ChannelBindingCallback,
    validator: &'a mut Validate<'a>,
    session_data: SessionData,
}

impl<'a> MechanismData<'a> {
    pub(crate) fn new(
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

impl MechanismData<'_> {
    pub(crate) fn validate(&mut self, provider: &dyn Provider) -> Result<(), ValidationError> {
        let context = build_context(provider);
        self.callback
            .validate(&self.session_data, context, self.validator)
    }

    pub(crate) fn callback<'a, 'b>(
        &'b self,
        provider: &'b dyn Provider,
        request: &'b mut Request<'a>,
    ) -> Result<(), SessionError> {
        let context = build_context(provider);
        match self.callback.callback(&self.session_data, context, request) {
            Ok(()) => Ok(()),
            Err(SessionError::CallbackError(CallbackError::EarlyReturn(_))) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn action<T>(&self, provider: &dyn Provider, value: &T::Value) -> Result<(), SessionError>
    where
        T: Property,
    {
        let mut tagged_option = TaggedOption::<'_, tags::Ref<Action<T>>>(Some(value));
        self.callback(provider, Request::new_action::<T>(&mut tagged_option))?;
        if tagged_option.is_some() {
            Err(SessionError::CallbackError(CallbackError::NoCallback))
        } else {
            Ok(())
        }
    }

    pub(crate) fn need<T, C>(&self, provider: &dyn Provider, mechcb: &mut C) -> Result<(), SessionError>
    where
        T: Property,
        C: CallbackRequest<T::Value>,
    {
        let mut tagged_option = TaggedOption::<'_, tags::RefMut<Satisfy<T>>>(Some(mechcb));
        self.callback(provider, Request::new_satisfy::<T>(&mut tagged_option))
    }

    pub(crate) fn need_with<T, F, G>(
        &self,
        provider: &dyn Provider,
        closure: &mut F,
    ) -> Result<G, SessionError>
    where
        T: Property,
        F: FnMut(&T::Value) -> Result<G, SessionError>,
    {
        self.maybe_need_with::<T, F, G>(provider, closure)?
            .ok_or(SessionError::CallbackError(CallbackError::NoCallback))
    }

    pub(crate) fn maybe_need_with<T, F, G>(
        &self,
        provider: &dyn Provider,
        closure: &mut F,
    ) -> Result<Option<G>, SessionError>
    where
        T: Property,
        F: FnMut(&T::Value) -> Result<G, SessionError>,
    {
        let mut closurecr = ClosureCR::<T, _, _>::wrap(closure);
        self.need::<T, _>(provider, &mut closurecr)?;
        Ok(closurecr.try_unwrap())
    }

    pub(crate) fn need_cb_data<F, G>(
        &self,
        cbname: &str,
        provider: &dyn Provider,
        f: &mut F,
    ) -> Result<G, SessionError>
    where
        F: FnMut(&[u8]) -> Result<G, SessionError>,
    {
        if let Some(cbdata) = self.chanbind_cb.get_cb_data(cbname) {
            f(cbdata)
        } else {
            self.need_with::<ChannelBindings, F, G>(provider, f)
        }
    }

    // Legacy bs:
    pub unsafe fn set_property_raw(&mut self, _prop: Gsasl_property, _: Arc<String>) {
        unimplemented!()
    }
    pub unsafe fn get_property<T>(&self) -> Option<&std::ffi::CStr> {
        unimplemented!()
    }
    pub unsafe fn get_property_or_callback<T>(&self) -> Result<Option<&str>, ()> {
        unimplemented!()
    }
}

// TODO: Since the Session object is only known to the protocol implementation and user they can
//       share a statically known Context.
pub struct SessionData {
    mechanism_desc: Mechanism,
    side: Side,
}

impl Debug for MechanismData<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
        match self {
            Self::Running => true,
            _ => false,
        }
    }
    #[inline(always)]
    pub fn is_finished(&self) -> bool {
        !self.is_running()
    }
}

/// Result type of a call to `step` or `step64`
///
/// See the documentation of [`Session::step`] for more details about this type
pub type StepResult = Result<(State, Option<usize>), SessionError>;

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
    use crate::context::EmptyProvider;
    use super::*;
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
                self.sasl.config.callback.as_ref(),
                &self.sasl.cb,
                validate,
                self.mechanism_desc,
                self.side,
            );
            mechanism_data.need_cb_data(cbname, &EmptyProvider, f)
        }
    }
}