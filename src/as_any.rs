use std::any::Any;

/// Trait upcasting for trait objects
///
/// This trait is required to be able to convert a &dyn Validation to a &dyn Any.
/// It has a blanked implementation for any `T: Any` so there is usually no need to implement
/// this trait by hand.
pub trait AsAny {
    fn as_any_super(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any_super(&self) -> &dyn Any { self }
}

#[macro_export]
macro_rules! eq_type {
    ($value:ident, $typeof:ty) => {
        $value.as_any_super().is::<$typeof>()
    };
    ($typeof:ty, $value:ident) => {
        $value.as_any_super().is::<$typeof>()
    };
}