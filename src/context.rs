use core::fmt;
use core::fmt::Write;
use crate::property::{Property, SizedProperty};
use crate::typed::tags::{MaybeSizedType, Type};
use crate::typed::{tags, Erased, Tagged};
use core::marker::PhantomData;
use core::ops::ControlFlow;

pub trait Provider<'a> {
    fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()>;
    fn provide_mut(&mut self, req: &mut Demand<'a>) -> DemandReply<()> {
        req.done()
    }
}

pub trait ProviderExt<'a>: Provider<'a> {
    fn and<P: Provider<'a>>(self, other: P) -> And<Self, P>
    where
        Self: Sized,
    {
        And { l: self, r: other }
    }
}
impl<'a, P: Provider<'a>> ProviderExt<'a> for P {}

#[derive(Debug)]
pub struct EmptyProvider;
impl Provider<'_> for EmptyProvider {
    fn provide(&self, _: &mut Demand<'_>) -> DemandReply<()> {
        DemandReply::Continue(())
    }
}

#[derive(Debug)]
pub struct And<L, R> {
    l: L,
    r: R,
}
impl<'a, L: Provider<'a>, R: Provider<'a>> Provider<'a> for And<L, R> {
    fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
        self.l.provide(req)?;
        self.r.provide(req)
    }

    fn provide_mut(&mut self, req: &mut Demand<'a>) -> DemandReply<()> {
        self.l.provide_mut(req)?;
        self.r.provide_mut(req)
    }
}

#[doc(hidden)]
pub struct TOKEN(PhantomData<()>);

impl fmt::Debug for TOKEN {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TOKEN")
    }
}
impl fmt::Display for TOKEN {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('_')
    }
}

/// Control-flow utility to help shortcut [`Demand::provide`]
///
/// This type allows to easily chain calls to [`provide`](Demand::provide) while exiting as soon
/// as possible by using [`std::ops::ControlFlow`].
pub type DemandReply<T> = ControlFlow<TOKEN, T>;

struct DemandTag<T>(PhantomData<T>);
impl<'a, T: Property<'a>> MaybeSizedType<'a> for DemandTag<T> {
    type Reified = T::Value;
}
impl<'a, T: SizedProperty<'a>> Type<'a> for DemandTag<T> {
    type Reified = T::Value;
}

#[repr(transparent)]
/// A type-erased demand for a Property
///
/// This struct is used by the [`Provider`] trait to request data from mechanisms that are not
/// necessarily of a `'static` lifetime.
pub struct Demand<'a>(dyn Erased<'a> + 'a);
impl<'a> Demand<'a> {
    pub(crate) fn new<T: tags::Type<'a>>(opt: &mut Tagged<'a, tags::Optional<T>>) -> &'a mut Self {
        unsafe { core::mem::transmute(opt as &mut dyn Erased) }
    }
}
impl<'a> Demand<'a> {
    pub fn done(&self) -> DemandReply<()> {
        DemandReply::Continue(())
    }

    fn provide<T: tags::Type<'a>>(&mut self, value: T::Reified) -> DemandReply<&mut Self> {
        if let Some(res ) = self.0.downcast_mut::<tags::Optional<T>>() {
            res.0 = Some(value);
            DemandReply::Break(TOKEN(PhantomData))
        } else {
            DemandReply::Continue(self)
        }
    }

    #[inline(always)]
    pub fn provide_ref<T: Property<'a>>(&mut self, value: &'a T::Value) -> DemandReply<&mut Self> {
        self.provide::<tags::Ref<DemandTag<T>>>(value)
    }

    #[inline(always)]
    pub fn provide_mut<T: Property<'a>>(&mut self, value: &'a mut T::Value) -> DemandReply<&mut Self> {
        self.provide::<tags::RefMut<DemandTag<T>>>(value)
    }
}

pub(crate) fn build_context<'a>(provider: &'a dyn Provider) -> &'a Context<'a> {
    unsafe { core::mem::transmute(provider) }
}

#[repr(transparent)]
pub struct Context<'a>(dyn Provider<'a>);
impl<'a> Context<'a> {
    #[inline]
    pub fn get_ref<P: Property<'a>>(&self) -> Option<&'a P::Value> {
        let mut tagged = Tagged::<'_, tags::Optional<tags::Ref<DemandTag<P>>>>(None);
        self.0.provide(Demand::new(&mut tagged));
        tagged.0
    }
    #[inline]
    pub fn get_mut<P: Property<'a>>(&mut self) -> Option<&'a mut P::Value> {
        let mut tagged = Tagged::<'_, tags::Optional<tags::RefMut<DemandTag<P>>>>(None);
        self.0.provide_mut(Demand::new(&mut tagged));
        tagged.0
    }
}

#[repr(transparent)]
pub struct ThisProvider<'a, P: Property<'a>>(&'a P::Value);
impl<'a, P: Property<'a>> ThisProvider<'a, P> {
    pub fn with(value: &'a P::Value) -> ThisProvider<'a, P> {
        ThisProvider(value)
    }
    fn back(&self) -> &'a P::Value {
        self.0
    }
}
impl<'a, P> Provider<'a> for ThisProvider<'a, P>
    where P: Property<'a>
{
    fn provide(&self, req: &mut Demand<'a>) -> DemandReply<()> {
        req.provide_ref::<P>(self.back())?.done()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thisprovider() {
        struct TestTag;
        impl Property<'_> for TestTag {
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
