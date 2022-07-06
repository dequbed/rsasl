//! Type-based property requesting
//!
//! rsasl has the rather complex task of making three independent pieces of code that don't know
//! anything about each other talk to and exchange complex data with each other; the
//! authentication mechanism needs to query information from both the user callback (e.g.
//! username, password) and from the protocol implementation (e.g. channel binding data).

use std::any::TypeId;
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
pub struct Demand<'a>(dyn Erased<'a> + 'a);
impl<'a> Demand<'a> {
    fn provide<T: tags::Type<'a>>(&mut self, value: T::Reified) -> &mut Self {
        if let Some(res @ TaggedOption(None)) = self.0.downcast_mut::<T>() {
            res.0 = Some(value)
        }
        self
    }

    pub fn provide_ref<T: MaybeSizedProperty>(&mut self, value: &'a T::Value) -> &mut Self {
        self.provide::<tags::Ref<tags::MaybeSizedValue<T::Value>>>(value)
    }
    pub fn provide_mut<T: MaybeSizedProperty>(&mut self, value: &'a mut T::Value) -> &mut Self {
        self.provide::<tags::RefMut<tags::MaybeSizedValue<T::Value>>>(value)
    }
}

#[repr(transparent)]
struct TaggedOption<'a, T: tags::Type<'a>>(Option<T::Reified>);
impl<'a, T: tags::Type<'a>> TaggedOption<'a, T> {
    unsafe fn as_demand(&mut self) -> &mut Demand<'a> {
        std::mem::transmute(self as &mut dyn Erased)
    }
}

trait Erased<'a>: 'a {
    fn tag_id(&self) -> TypeId;
}
impl<'a, T: tags::Type<'a>> Erased<'a> for TaggedOption<'a, T> {
    fn tag_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
}
impl<'a> dyn Erased<'a> {
    #[inline]
    fn is<T: tags::Type<'a>>(&self) -> bool {
        TypeId::of::<T>() == self.tag_id()
    }

    #[inline]
    fn downcast_mut<T: tags::Type<'a>>(&mut self) -> Option<&mut TaggedOption<'a, T>> {
        if self.is::<T>() {
            Some(unsafe { &mut *(self as *mut Self as *mut TaggedOption<'a, T>) })
        } else {
            None
        }
    }
}
