use crate::callback::tags;
use std::fmt::{Debug, Display, Formatter};

pub trait Validation<'a>: tags::Type<'a> {}
