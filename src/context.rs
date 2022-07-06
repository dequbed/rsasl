use crate::property::MaybeSizedProperty;
use crate::typed::{Erased, TaggedOption, tags};

pub trait Provider {
    fn provide<'a>(&'a self, req: &mut Demand<'a>);
    fn provide_mut<'a>(&'a mut self, _req: &mut Demand<'a>) {}
}

impl Provider for () {
    fn provide<'a>(&'a self, _: &mut Demand<'a>) {}
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
    pub fn get_ref<P: MaybeSizedProperty>(&self) -> Option<&P::Value> {
        self.get_by_tag::<tags::Ref<tags::MaybeSizedValue<P::Value>>>()
    }
    #[inline]
    pub fn get_mut<P: MaybeSizedProperty>(&self) -> Option<&mut P::Value> {
        self.get_by_tag::<tags::RefMut<tags::MaybeSizedValue<P::Value>>>()
    }
}

#[repr(transparent)]
pub struct ThisProvider<'a, P: MaybeSizedProperty>(&'a P::Value);
impl<P: MaybeSizedProperty> ThisProvider<'_, P> {
    pub fn with(value: &P::Value) -> ThisProvider<'_, P> {
        ThisProvider(value)
    }
    fn back(&self) -> &P::Value {
        self.0
    }
}
impl<P: MaybeSizedProperty> Provider for ThisProvider<'_, P> {
    fn provide<'a>(&'a self, req: &mut Demand<'a>) {
        req.provide_ref::<P>(self.back());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanisms::plain::server::PlainValidation;
    use std::ptr::NonNull;

    #[test]
    fn test_thisprovider() {
        struct TestTag;
        impl MaybeSizedProperty for TestTag {
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