use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::sync::Arc;

use crate::callback::{CallbackError, CallbackRequest, ClosureCR, Request, RequestResponse, RequestTag};
use crate::channel_bindings::ChannelBindingCallback;
use crate::error::SessionError;
use crate::gsasl::consts::Gsasl_property;
use crate::mechanism::Authentication;
use crate::validate::*;
use crate::{Mechanism, SessionCallback};
use crate::context::{build_context, Provider};
use crate::property::MaybeSizedProperty;
use crate::typed::{TaggedOption, tags};

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

    pub fn with_channel_binding(
        self,
        channel_binding_cb: Box<dyn ChannelBindingCallback>,
    ) -> Session {
        Session::new(
            self.callback,
            self.mechanism,
            self.mechanism_desc,
            self.side,
            Some(channel_binding_cb),
        )
    }

    pub fn without_channel_binding(self) -> Session {
        Session::new(
            self.callback,
            self.mechanism,
            self.mechanism_desc,
            self.side,
            None,
        )
    }
}

pub struct Session {
    mechanism: Box<dyn Authentication>,
    mechanism_data: MechanismData,
}

impl Session {
    pub(crate) fn new(
        callback: Arc<dyn SessionCallback>,
        mechanism: Box<dyn Authentication>,
        mechanism_desc: Mechanism,
        side: Side,
        channel_binding_cb: Option<Box<dyn ChannelBindingCallback>>,
    ) -> Self {
        Self {
            mechanism,
            mechanism_data: MechanismData::new(callback, channel_binding_cb, mechanism_desc, side),
        }
    }

    #[inline(always)]
    pub fn are_we_first(&self) -> bool {
        self.mechanism_data.session_data.side
            == self.mechanism_data.session_data.mechanism_desc.first
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
    pub fn step(&mut self, input: Option<&[u8]>, writer: &mut impl Write) -> StepResult {
        if let Some(input) = input {
            self.mechanism
                .step(&mut self.mechanism_data, Some(input.as_ref()), writer)
        } else {
            self.mechanism.step(&mut self.mechanism_data, None, writer)
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
    pub fn step64(&mut self, input: Option<&[u8]>, writer: &mut impl Write) -> StepResult {
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

pub struct MechanismData {
    callback: Arc<dyn SessionCallback>,
    channel_binding_cb: Option<Box<dyn ChannelBindingCallback>>,
    session_data: SessionData,
}

impl MechanismData {
    pub(crate) fn new(
        callback: Arc<dyn SessionCallback>,
        channel_binding_cb: Option<Box<dyn ChannelBindingCallback>>,
        mechanism_desc: Mechanism,
        side: Side,
    ) -> Self {
        Self {
            callback,
            channel_binding_cb,
            session_data: SessionData::new(mechanism_desc, side),
        }
    }

    pub fn validate<V, P>(&self, provider: &P) -> Result<V::Value, ValidationError>
    where
        V: Validation,
        P: Provider,
    {
        let mut tagged_option = TaggedOption::<'_, V>(None);
        let context = build_context(provider);
        let validate = Validate::new::<V>(&mut tagged_option);
        let cflow = self.callback.validate(&self.session_data, context, validate);
        if let RequestResponse::Continue(err) = cflow {
            Err(err)
        } else {
            Ok(tagged_option.0.unwrap())
        }
    }

    pub fn callback<'a, 'b, P: Provider>(
        &'b self,
        provider: &'b P,
        request: &'b mut Request<'a>,
    ) -> Result<(), CallbackError> {
        let context = build_context(provider);
        let cflow = self.callback.callback(&self.session_data, context, request);

        if let RequestResponse::Continue(err) = cflow {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn need<T, C, P>(&self, provider: &P, mechcb: &mut C) -> Result<(), CallbackError>
    where
        T: MaybeSizedProperty,
        C: CallbackRequest<T::Value>,
        P: Provider,
    {
        let mut tagged_option = TaggedOption::<'_, tags::RefMut<RequestTag<T>>>(Some(mechcb));
        self.callback(provider, Request::new::<T>(&mut tagged_option))?;
        if tagged_option.is_some() {
            Err(CallbackError::NoCallback)
        } else {
            Ok(())
        }
    }

    pub fn need_with<T: MaybeSizedProperty, F: FnMut(&T::Value), P>(
        &self,
        provider: &P,
        closure: &mut F,
    ) -> Result<(), CallbackError>
    where
        P: Provider,
    {
        let closurecr = ClosureCR::<T, F>::wrap(closure);
        self.need::<T, _, P>(provider, closurecr)
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

impl Debug for MechanismData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionData").finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthenticationError {}

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
pub struct StepOutcome {
    pub step: Step,
    pub data_len: Option<usize>,
}
pub type StepResult = Result<Step, SessionError>;


impl SessionData {
    pub(crate) fn new(mechanism_desc: Mechanism, side: Side) -> Self {
        Self {
            mechanism_desc,
            side,
        }
    }
}

impl SessionData {}
