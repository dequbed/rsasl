use crate::{Mechname, SASLError};
use crate::property::Property;
use crate::SASLError::{NoCallback, NoValidate};
use crate::session::SessionData;
use crate::validate::Validation;

pub trait Callback {
    /// Query by a mechanism implementation to provide some information
    ///
    /// The parameter `property` defines the exact property that is requested. In most cases a
    /// callback should then issue a call to [`SessionData::set_property`], so e.g.
    /// ```rust
    /// # use rsasl::callback::Callback;
    /// # use rsasl::error::SASLError;
    /// # use rsasl::error::SASLError::NoCallback;
    /// # use rsasl::Property;
    /// use rsasl::property::{properties, Password};
    /// # use rsasl::session::SessionData;
    /// # struct CB;
    /// # impl Callback for CB {
    /// fn provide_prop(&self, session: &mut SessionData, property: Property) -> Result<(), SASLError> {
    ///     match property {
    ///         properties::PASSWORD => {
    ///             session.set_property::<Password>(Box::new("secret".to_string()));
    ///             Ok(())
    ///         }
    ///         _ => {
    ///             Err(NoCallback { property })
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// In some cases (e.g. [`OpenID20AuthenticateInBrowser`] the mechanism expects that a certain
    /// action is taken by the user instead of an explicit property being provided (e.g. to
    /// authenticate to their OIDC IdP using the system's web browser).
    fn provide_prop(&self, _session: &mut SessionData, property: Property)
        -> Result<(), SASLError>
    {
        return Err(NoCallback { property })
    }

    /// Validate an authentication exchange
    ///
    /// This callback will only be issued on the server side of an authentication exchange to
    /// validate the data passed in by the client side. Some mechanisms do not use this validation
    /// system at all and instead only issue calls to [`provide_prop`], e.g. the (S)CRAM and DIGEST
    /// family of mechanisms. Check the documentation of the mechanisms you need to support for
    /// details on how to authenticate users server side.
    ///
    /// If used the `validation` parameter defines the exact validation to be performed. Most
    /// mechanisms in this crate define their own validation system, with the exception of
    /// `PLAIN` and `LOGIN` which both use [`SIMPLE`] (username / password) as validation.
    ///
    /// See the [`validate module documentation`](crate::validate) for details on how to
    /// implement each validation.
    fn validate(&self, _session: &mut SessionData, validation: Validation, _mechanism: &Mechname)
        -> Result<(), SASLError>
    {
        return Err(NoValidate { validation })
    }
}
