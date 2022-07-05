use std::fmt::{Debug, Display, Formatter};
use crate::callback::tags;

pub trait Validation<'a>: tags::Type<'a> {
}