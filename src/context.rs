use crate::property::MaybeSizedProperty;
use crate::typed::{Demand, tags};

pub trait Provider {
    fn provide<'a>(&'a self, req: &mut Demand<'a>);
    fn provide_mut<'a>(&'a mut self, _req: &mut Demand<'a>) {}
}

impl Provider for () {
    fn provide<'a>(&'a self, _: &mut Demand<'a>) {}
}


pub(crate) fn build_context(provider: &dyn Provider) -> &Context {
    unsafe { std::mem::transmute(provider) }
}

#[repr(transparent)]
pub struct Context(dyn Provider);
impl Context {
    fn get_by_tag<'cx, T: tags::Type<'cx>>(&'cx self) -> Option<T::Reified> {
        let mut tagged_option = TaggedOption::<'cx, T>(None);
        self.0.provide(unsafe { tagged_option.as_demand() });
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
pub struct ThisProvider<P: MaybeSizedProperty>(P::Value);
impl<P: MaybeSizedProperty> ThisProvider<P> {
    pub fn with(value: &P::Value) -> &Self {
        unsafe { std::mem::transmute(value) }
    }
    fn back(&self) -> &P::Value {
        unsafe { std::mem::transmute(self) }
    }
    fn back_mut(&mut self) -> &mut P::Value {
        unsafe { std::mem::transmute(self) }
    }
}
impl<P: MaybeSizedProperty> Provider for ThisProvider<P> {
    fn provide<'a>(&'a self, req: &mut Demand<'a>) {
        req.provide_ref::<P>(self.back());
    }
    fn provide_mut<'a>(&'a mut self, req: &mut Demand<'a>) {
        req.provide_ref::<P>(self.back())
           .provide_mut::<P>(self.back_mut());
    }
}
