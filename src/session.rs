use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::callback::{Action, CallbackError, CallbackRequest, ClosureCR, Request, Satisfy};
use crate::channel_bindings::ChannelBindingCallback;
use crate::context::{build_context, Provider};
use crate::error::SessionError;
use crate::gsasl::consts::Gsasl_property;
use crate::mechanism::Authentication;
use crate::property::MaybeSizedProperty;
use crate::typed::{tags, TaggedOption};
use crate::validate::*;
use crate::{Mechanism, SessionCallback};

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}

pub struct SessionBuilder {
    callback: Arc<dyn SessionCallback>,
    mechanism: Box<dyn Authentication>,
    mechanism_desc: Mechanism,
    side: Side,
}
impl SessionBuilder {
    pub fn new(
        callback: Arc<dyn SessionCallback>,
        mechanism: Box<dyn Authentication>,
        mechanism_desc: Mechanism,
        side: Side,
    ) -> Self {
        Self {
            callback,
            mechanism,
            mechanism_desc,
            side,
        }
    }

    pub fn with_channel_binding<V: Validation>(
        self,
        channel_binding_cb: Box<dyn ChannelBindingCallback>,
    ) -> Session<V> {
        Session::new(
            self.callback,
            self.mechanism,
            self.mechanism_desc,
            self.side,
            Some(channel_binding_cb),
        )
    }

    pub fn without_channel_binding<V: Validation>(self) -> Session<V> {
        Session::new(
            self.callback,
            self.mechanism,
            self.mechanism_desc,
            self.side,
            None,
        )
    }
}

pub struct Session<V: Validation> {
    callback: Arc<dyn SessionCallback>,
    mechanism: Box<dyn Authentication>,
    mechanism_desc: Mechanism,
    side: Side,
    _marker: PhantomData<V>,
}

impl<V: Validation> Session<V> {
    pub(crate) fn new(
        callback: Arc<dyn SessionCallback>,
        mechanism: Box<dyn Authentication>,
        mechanism_desc: Mechanism,
        side: Side,
        _channel_binding_cb: Option<Box<dyn ChannelBindingCallback>>,
    ) -> Self {
        Self {
            callback,
            mechanism,
            mechanism_desc,
            side,
            _marker: PhantomData,
        }
    }

    #[inline(always)]
    pub fn are_we_first(&self) -> bool {
        self.side == self.mechanism_desc.first
    }
}

#[cfg(feature = "provider")]
impl<V: Validation> Session<V> {
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
    pub fn step(
        &mut self,
        input: Option<&[u8]>,
        writer: &mut impl Write,
    ) -> Result<(Option<V::Value>, Option<usize>), SessionError> {
        let mut tagged_option = TaggedOption::<'_, V>(None);

        let (state, written) = {
            let validate = Validate::new::<V>(&mut tagged_option);
            let mut mechanism_data = MechanismData::new(
                self.callback.as_ref(),
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
            let value = tagged_option.0.take().ok_or(SessionError::NoValidate)?;
            Ok((Some(value), written))
        } else {
            Ok((None, written))
        }
    }
}

#[cfg(feature = "provider_base64")]
impl<V: Validation> Session<V> {
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
    ) -> Result<(Option<V::Value>, Option<usize>), SessionError> {
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
    validator: &'a mut Validate<'a>,
    session_data: SessionData,
}

impl<'a> MechanismData<'a> {
    pub(crate) fn new(
        callback: &'a dyn SessionCallback,
        validator: &'a mut Validate<'a>,
        mechanism_desc: Mechanism,
        side: Side,
    ) -> Self {
        Self {
            callback,
            validator,
            session_data: SessionData::new(mechanism_desc, side),
        }
    }
}

impl MechanismData<'_> {
    pub fn validate(&mut self, provider: &dyn Provider) -> Result<(), ValidationError> {
        let context = build_context(provider);
        self.callback
            .validate(&self.session_data, context, self.validator)
    }

    pub fn callback<'a, 'b>(
        &'b self,
        provider: &'b dyn Provider,
        request: &'b mut Request<'a>,
    ) -> Result<(), CallbackError> {
        let context = build_context(provider);
        self.callback.callback(&self.session_data, context, request)
    }

    pub fn action<T>(&self, provider: &dyn Provider, value: &T::Value) -> Result<(), CallbackError>
    where
        T: MaybeSizedProperty,
    {
        let mut tagged_option = TaggedOption::<'_, tags::Ref<Action<T>>>(Some(value));
        self.callback(provider, Request::new_action::<T>(&mut tagged_option))
    }

    pub fn need<T, C>(&self, provider: &dyn Provider, mechcb: &mut C) -> Result<(), CallbackError>
    where
        T: MaybeSizedProperty,
        C: CallbackRequest<T::Value>,
    {
        let mut tagged_option = TaggedOption::<'_, tags::RefMut<Satisfy<T>>>(Some(mechcb));
        self.callback(provider, Request::new_satisfy::<T>(&mut tagged_option))?;
        if tagged_option.is_some() {
            Err(CallbackError::NoCallback)
        } else {
            Ok(())
        }
    }

    pub fn need_with<T: MaybeSizedProperty, F: FnMut(&T::Value)>(
        &self,
        provider: &dyn Provider,
        closure: &mut F,
    ) -> Result<(), CallbackError> {
        let closurecr = ClosureCR::<T, F>::wrap(closure);
        self.need::<T, _>(provider, closurecr)
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
