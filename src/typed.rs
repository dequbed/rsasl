//! Type-based property requesting
//!
//! rsasl has the rather complex task of making three independent pieces of code that don't know
//! anything about each other talk to and exchange complex data with each other; the
//! authentication mechanism needs to query information from both the user callback (e.g.
//! username, password) and from the protocol implementation (e.g. channel binding data).

use core::any::TypeId;
use core::ops::Deref;
use core::ops::DerefMut;

pub mod tags {
    use core::marker::PhantomData;

    pub trait Type<'a>: 'static + Sized {
        type Reified: 'a;
    }

    pub trait MaybeSizedType<'a>: 'static + Sized {
        type Reified: 'a + ?Sized;
    }

    pub struct Ref<T>(PhantomData<T>);
    impl<'a, T: MaybeSizedType<'a>> Type<'a> for Ref<T> {
        type Reified = &'a T::Reified;
    }

    pub struct RefMut<T>(PhantomData<T>);
    impl<'a, T: MaybeSizedType<'a>> Type<'a> for RefMut<T> {
        type Reified = &'a mut T::Reified;
    }

    pub struct Optional<T>(PhantomData<T>);
    impl<'a, T: Type<'a>> Type<'a> for Optional<T> {
        type Reified = Option<T::Reified>;
    }
}

#[repr(transparent)]
pub struct Tagged<'a, T: tags::Type<'a>>(pub(crate) T::Reified);
impl<'a, T: tags::Type<'a>> Deref for Tagged<'a, T> {
    type Target = T::Reified;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<'a, T: tags::Type<'a>> DerefMut for Tagged<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A trait to safely type-erase non-`'static` values
///
/// [`std::any::Any`] allows similar dynamic typing, but can not store values with lifetimes
/// associated like references (e.g. `&str`). This trait encodes the lifetimes of the objects as
/// well, allowing to safely type-erase e.g. a `&'a str`. This trait is the fundamental mechanic
/// behind [`Context`](crate::context::Context) and [`Request`](crate::callback::Request).
pub trait Erased<'a>: 'a {
    fn tag_id(&self) -> TypeId;
}
impl<'a, T: tags::Type<'a>> Erased<'a> for Tagged<'a, T> {
    fn tag_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
}
impl<'a> dyn Erased<'a> {
    #[inline]
    pub(crate) fn is<'p, T: tags::Type<'p>>(&self) -> bool {
        TypeId::of::<T>() == self.tag_id()
    }

    #[inline]
    pub(crate) fn downcast_mut<'p, T: tags::Type<'p>>(&mut self) -> Option<&mut Tagged<'p, T>> {
        if self.is::<T>() {
            Some(unsafe { &mut *(self as *mut Self).cast::<Tagged<T>>() })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback::Action;
    use crate::property::AuthId;

    #[test]
    fn cant_outlive() {
        let value = String::from("hello world");
        let _tagged = Tagged::<Action<AuthId>>(Some(value.as_ref()));
    }
}
