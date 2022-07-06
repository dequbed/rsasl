//! Type-based property requesting
//!
//! rsasl has the rather complex task of making three independent pieces of code that don't know
//! anything about each other talk to and exchange complex data with each other; the
//! authentication mechanism needs to query information from both the user callback (e.g.
//! username, password) and from the protocol implementation (e.g. channel binding data).

use std::any::TypeId;
use std::ops::{Deref, DerefMut};
use crate::property::MaybeSizedProperty;

pub(crate) mod tags {
    use std::marker::PhantomData;

    pub trait Type<'a>: 'static + Sized {
        type Reified: 'a;
    }

    pub trait MaybeSizedType<'a>: 'static + Sized {
        type Reified: 'a + ?Sized;
    }
    impl<'a, T: Type<'a>> MaybeSizedType<'a> for T {
        type Reified = T::Reified;
    }

    pub struct Value<T: 'static>(PhantomData<T>);
    impl<'a, T: 'static> Type<'a> for Value<T> {
        type Reified = T;
    }

    pub struct MaybeSizedValue<T: 'static + ?Sized>(PhantomData<T>);
    impl<'a, T: 'static + ?Sized> MaybeSizedType<'a> for MaybeSizedValue<T> {
        type Reified = T;
    }

    pub struct Ref<T>(PhantomData<T>);
    impl<'a, T: MaybeSizedType<'a>> Type<'a> for Ref<T> {
        type Reified = &'a T::Reified;
    }

    pub struct RefMut<T>(PhantomData<T>);
    impl<'a, T: MaybeSizedType<'a>> Type<'a> for RefMut<T> {
        type Reified = &'a mut T::Reified;
    }
}

#[repr(transparent)]
/// An option made covariant over a tagged type `T`
///
/// This is the only possible implementation of [`Erased`] allowing safe casts to be made under
/// this assumption.
pub(crate) struct TaggedOption<'a, T: tags::Type<'a>>(pub(crate) Option<T::Reified>);
impl<'a, T: tags::Type<'a>> Deref for TaggedOption<'a, T> {
    type Target = Option<T::Reified>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<'a, T: tags::Type<'a>> DerefMut for TaggedOption<'a, T> {
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
pub(crate) trait Erased<'a>: 'a {
    fn tag_id(&self) -> TypeId;
}
impl<'a, T: tags::Type<'a>> Erased<'a> for TaggedOption<'a, T> {
    fn tag_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
}
impl<'a> dyn Erased<'a> {
    #[inline]
    pub fn is<T: tags::Type<'a>>(&self) -> bool {
        TypeId::of::<T>() == self.tag_id()
    }

    #[inline]
    pub fn downcast_mut<T: tags::Type<'a>>(&mut self) -> Option<&mut TaggedOption<'a, T>> {
        if self.is::<T>() {
            Some(unsafe { &mut *(self as *mut Self as *mut TaggedOption<'a, T>) })
        } else {
            None
        }
    }
}
