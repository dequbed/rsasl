use crate::property::{Property, SizedProperty};
use crate::typed::tags::{MaybeSizedType, Type};
use crate::typed::{tags, Erased, TaggedOption};
use std::marker::PhantomData;
use std::ops::ControlFlow;

pub trait Provider {
    fn provide<'a>(&'a self, req: &mut Demand<'a>) -> DemandReply<()>;
    fn provide_mut<'a>(&'a mut self, _req: &mut Demand<'a>) -> DemandReply<()> {
        DemandReply::Continue(())
    }
}

#[derive(Debug)]
pub struct EmptyProvider;
impl Provider for EmptyProvider {
    fn provide<'a>(&'a self, _: &mut Demand<'a>) -> DemandReply<()> {
        DemandReply::Continue(())
    }
}

#[doc(hidden)]
pub struct TOKEN(PhantomData<()>);

/// Control-flow utility to help shortcut [`Demand::provide`]
///
/// This type allows to easily chain calls to [`provide`](Demand::provide) while exiting as soon
/// as possible by using [`std::ops::ControlFlow`].
pub type DemandReply<T> = ControlFlow<TOKEN, T>;

struct DemandTag<T>(PhantomData<T>);
impl<'a, T: Property> MaybeSizedType<'a> for DemandTag<T> {
    type Reified = T::Value;
}
impl<'a, T: SizedProperty> Type<'a> for DemandTag<T> {
    type Reified = T::Value;
}

#[repr(transparent)]
/// A type-erased demand for a Property
///
/// This struct is used by the [`Provider`] trait to request data from mechanisms that are not
/// necessarily of a `'static` lifetime.
pub struct Demand<'a>(dyn Erased<'a> + 'a);
impl<'a> Demand<'a> {
    pub(crate) fn new<T: tags::Type<'a>>(opt: &mut TaggedOption<'a, T>) -> &'a mut Self {
        unsafe { std::mem::transmute(opt as &mut dyn Erased) }
    }
}
impl<'a> Demand<'a> {
    pub fn done(&self) -> DemandReply<()> {
        DemandReply::Continue(())
    }

    fn provide<T: tags::Type<'a>>(&mut self, value: T::Reified) -> DemandReply<&mut Self> {
        if let Some(res @ TaggedOption(None)) = self.0.downcast_mut::<T>() {
            res.0 = Some(value);
            DemandReply::Break(TOKEN(PhantomData))
        } else {
            DemandReply::Continue(self)
        }
    }

    pub fn provide_ref<T: Property>(
        &mut self,
        value: &'a T::Value,
    ) -> DemandReply<&mut Self> {
        self.provide::<tags::Ref<DemandTag<T>>>(value)
    }
    pub fn provide_mut<T: Property>(
        &mut self,
        value: &'a mut T::Value,
    ) -> DemandReply<&mut Self> {
        self.provide::<tags::RefMut<DemandTag<T>>>(value)
    }
}

pub(crate) fn build_context(provider: &dyn Provider) -> &Context {
    unsafe { std::mem::transmute(provider) }
}

#[repr(transparent)]
pub struct Context(dyn Provider);
impl Context {
    fn get_by_tag<'cx, T: tags::Type<'cx>>(&'cx self) -> Option<T::Reified> {
        let mut tagged_option = TaggedOption::<'cx, T>(None);
        self.0.provide(Demand::new(&mut tagged_option));
        tagged_option.0
    }
    #[inline]
    // TODO: this should probably return a Result to make it's use in callbacks easier?
    pub fn get_ref<P: Property>(&self) -> Option<&P::Value> {
        self.get_by_tag::<tags::Ref<DemandTag<P>>>()
    }
    #[inline]
    pub fn get_mut<P: Property>(&self) -> Option<&mut P::Value> {
        self.get_by_tag::<tags::RefMut<DemandTag<P>>>()
    }
}

#[repr(transparent)]
pub struct ThisProvider<'a, P: Property>(&'a P::Value);
impl<P: Property> ThisProvider<'_, P> {
    pub fn with(value: &P::Value) -> ThisProvider<'_, P> {
        ThisProvider(value)
    }
    fn back(&self) -> &P::Value {
        self.0
    }
}
impl<P: Property> Provider for ThisProvider<'_, P> {
    fn provide<'a>(&'a self, req: &mut Demand<'a>) -> DemandReply<()> {
        req.provide_ref::<P>(self.back())?.done()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thisprovider() {
        struct TestTag;
        impl Property for TestTag {
            type Value = str;
        }
        let value = "hello ";
        let p = ThisProvider::<TestTag>::with(&value);
        let value2 = "world!";
        let p2 = ThisProvider::<TestTag>::with(&value2);
        let ctx = build_context(&p);
        assert_eq!(ctx.get_ref::<TestTag>().unwrap(), value);
        let ctx2 = build_context(&p2);
        assert_eq!(ctx2.get_ref::<TestTag>().unwrap(), value2);
    }
}
