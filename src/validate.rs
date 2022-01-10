use std::any::{Any, TypeId};
use std::fmt::{Debug, Display, Formatter};
use crate::as_any::AsAny;

/// Marker trait for expected validation in a callback.
/// Only ever passed as `&'static dyn Validation` trait object
pub trait Validation: 'static + Display + Debug + AsAny {
    fn as_any(&self) -> &dyn Any {
        <Self as AsAny>::as_any_super(self)
    }

    fn as_const() -> &'static dyn Validation where Self: Sized {
        todo!()
    }
}

#[derive(Debug)]
pub struct Simple;
impl Display for Simple {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("simple username/password based auth")
    }
}
impl Validation for Simple {}

pub const SIMPLE: Simple = Simple;

#[derive(Debug)]
pub struct OpenID20;
impl Display for OpenID20 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("simple username/password based auth")
    }
}
impl Validation for OpenID20 {}

pub const OPENID20: OpenID20 = OpenID20;

#[derive(Debug)]
pub struct Saml20;
impl Display for Saml20 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("simple username/password based auth")
    }
}
impl Validation for Saml20 {}

pub const SAML20: Saml20 = Saml20;

#[derive(Debug)]
pub struct SecurId;
impl Display for SecurId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("simple username/password based auth")
    }
}
impl Validation for SecurId {}

pub const SECURID: SecurId = SecurId;

#[derive(Debug)]
pub struct Gssapi;
impl Display for Gssapi {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("simple username/password based auth")
    }
}
impl Validation for Gssapi {}

pub const GSSAPI: Gssapi = Gssapi;

#[derive(Debug)]
pub struct Anonymous;
impl Display for Anonymous {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("simple username/password based auth")
    }
}
impl Validation for Anonymous {}

pub const ANONYMOUS: Anonymous = Anonymous;

#[derive(Debug)]
pub struct External;
impl Display for External {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("simple username/password based auth")
    }
}
impl Validation for External {}

pub const EXTERNAL: External = External;

#[cfg(test)]
mod tests {
    use std::any::TypeId;
    use std::collections::HashMap;
    use std::ptr::null_mut;
    use crate::{Callback, eq_type, SASLError};
    use crate::SASLError::NoValidate;
    use crate::session::SessionData;
    use super::*;

    #[test]
    fn test_validation_callback() {
        struct TestCallback;
        impl Callback for TestCallback {
            fn validate(&self, session: &mut SessionData, validation: &'static dyn Validation)
                -> Result<(), SASLError>
            {
                if eq_type!(validation, Simple) {
                    println!("Hey I know how to validate simple!");
                    Ok(())
                } else {
                    println!("Huh, I don't know how to validate {} ({:?})", validation, validation);
                    Err(NoValidate { validation })
                }
            }
        }

        let cb = TestCallback;
        let s = unsafe { &mut *null_mut() as &mut SessionData };
        cb.validate(s, &SIMPLE).unwrap();
        cb.validate(s, &OPENID20).unwrap_err();
    }

    #[test]
    fn test_differentiable() {
        let typeid_a = TypeId::of::<Simple>();
        let typeid_b = TypeId::of::<SecurId>();

        assert_ne!(typeid_a, typeid_b);

        let mut map: HashMap<TypeId, u32> = HashMap::new();

        let o = map.insert(typeid_a, 0xDEADBEEF);
        assert!(o.is_none());

        let o = map.insert(typeid_b, 0xCAFEBABE);
        assert!(o.is_none());

        assert_eq!(map.get(&typeid_a), Some(&0xDEADBEEF));
        assert_eq!(map.get(&typeid_b), Some(&0xCAFEBABE));
    }
}