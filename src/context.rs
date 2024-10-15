use crate::property::{Property, SizedProperty};
use crate::typed::tags::{MaybeSizedType, Type};
use crate::typed::{tags, Erased, Tagged};
use core::fmt;
use core::fmt::Write;
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

#[allow(clippy::exhaustive_structs)]
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
pub struct Token(PhantomData<()>);

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TOKEN")
    }
}
impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('_')
    }
}

/// Control-flow utility to help shortcut [`Demand::provide_ref`]/[`Demand::provide_mut`]
///
/// This type allows to easily chain calls while exiting as soon as possible by using
/// [`std::ops::ControlFlow`].
pub type DemandReply<T> = ControlFlow<Token, T>;

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
        unsafe { &mut *(opt as &mut dyn Erased as *mut dyn Erased as *mut Self) }
    }
}
impl<'a> Demand<'a> {
    #[allow(clippy::unused_self)]
    pub const fn done(&self) -> DemandReply<()> {
        DemandReply::Continue(())
    }

    fn provide<T: tags::Type<'a>>(&mut self, value: T::Reified) -> DemandReply<&mut Self> {
        if let Some(res) = self.0.downcast_mut::<tags::Optional<T>>() {
            res.0 = Some(value);
            DemandReply::Break(Token(PhantomData))
        } else {
            DemandReply::Continue(self)
        }
    }

    #[inline(always)]
    pub fn provide_ref<T: Property<'a>>(&mut self, value: &'a T::Value) -> DemandReply<&mut Self> {
        self.provide::<tags::Ref<DemandTag<T>>>(value)
    }

    #[inline(always)]
    pub fn provide_mut<T: Property<'a>>(
        &mut self,
        value: &'a mut T::Value,
    ) -> DemandReply<&mut Self> {
        self.provide::<tags::RefMut<DemandTag<T>>>(value)
    }
}

pub fn build_context<'a, 'b>(provider: &'a (dyn Provider<'b> + 'a)) -> &'a Context<'b> {
    unsafe { &*(provider as *const dyn Provider as *const Context) }
}

#[repr(transparent)]
/// Strongly typed dynamic value access
///
/// Values a mechanism makes available can be queried using [`get_ref`](Context::get_ref) and
/// [`get_mut`](Context::get_mut). These methods are generic over the [`Property`] and return
/// its associated type [`Property::Value`]. This allows e.g. both [`AuthId`] and [`Realm`] to
/// return values of type `&str`.
///
/// Which values are available depends on the mechanism instance, refer to its documentation for
/// details.
///
/// **Note**: Querying a property that is available for the mechanism but is not set will still
/// return `Some`. So e.g. in a PLAIN exchange `get_ref<Authzid>` will return `Some("")` if no
/// authzid was transmitted.
///
/// This struct thus implements a similar functionality to the (at the time of writing unstable)
/// [provide_any/Provider system](https://doc.rust-lang.org/std/any/trait.Provider.html).
/// The main difference between `Provider` and `Context` is that the latter uses the above
/// mentioned layer of indirection: The generic parameter implementing
/// [`Property<'a>`] specifies the type being returned (i.e. [`Property::Value`]) <br/>
/// [(read more..)](crate::docs::adr::adr0002_context_vs_provide_any)
///
/// [`AuthId`]: crate::property::AuthId
/// [`Realm`]: crate::property::Realm
pub struct Context<'a>(dyn Provider<'a>);
impl<'a> Context<'a> {
    #[inline]
    /// Query the value of a given Property
    ///
    /// This will return `Some(&P::Value)` if the given property is available for the running
    /// mechanism.
    ///
    /// **Note**: this method will also return `Some` if the property is available with the given
    /// mechanism but does not have a value, for example because it is optional. In those cases the
    /// value will be a specific sentinel indicating that fact.
    /// (e.g. `get_ref<Authzid>` returns `Some("")` in `PLAIN` exchanges if no authzid was send by
    /// the client)
    ///
    /// ```no_run
    /// # let context: &rsasl::callback::Context<'_> = unimplemented!();
    /// if let Some("EXAMPLE.COM") = context.get_ref::<rsasl::property::Realm>() {
    ///     // Special handling
    /// }
    /// ```
    pub fn get_ref<P: Property<'a>>(&self) -> Option<&'a P::Value> {
        let mut tagged = Tagged::<'_, tags::Optional<tags::Ref<DemandTag<P>>>>(None);
        self.0.provide(Demand::new(&mut tagged));
        tagged.0
    }

    #[inline]
    /// Request mutable access to the value of a given Property
    ///
    /// This will return `None` if the given property is not available for the running mechanism,
    /// **or** if the mechanism does not allow mutable access to its value.
    pub fn get_mut<P: Property<'a>>(&mut self) -> Option<&'a mut P::Value> {
        let mut tagged = Tagged::<'_, tags::Optional<tags::RefMut<DemandTag<P>>>>(None);
        self.0.provide_mut(Demand::new(&mut tagged));
        tagged.0
    }
}

#[repr(transparent)]
pub struct ThisProvider<'a, P: Property<'a>>(&'a P::Value);
impl<'a, P: Property<'a>> ThisProvider<'a, P> {
    pub const fn with(value: &'a P::Value) -> Self {
        ThisProvider(value)
    }

    const fn back(&self) -> &'a P::Value {
        self.0
    }
}

impl<'a, P> Provider<'a> for ThisProvider<'a, P>
where
    P: Property<'a>,
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
        let p = ThisProvider::<TestTag>::with(value);
        let value2 = "world!";
        let p2 = ThisProvider::<TestTag>::with(value2);
        let ctx = build_context(&p);
        assert_eq!(ctx.get_ref::<TestTag>().unwrap(), value);
        let ctx2 = build_context(&p2);
        assert_eq!(ctx2.get_ref::<TestTag>().unwrap(), value2);
    }

    static_assertions::assert_obj_safe!(Provider);
}
