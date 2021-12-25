use crate::mechanisms::plain::client::Plain;
use crate::Mech;

pub trait Registry {
    fn new() -> Self;
}

pub struct DynamicRegistry {
    mechs: Vec<Box<dyn Mech>>,
}

impl Registry for DynamicRegistry {
    fn new() -> Self {
        Self {
            mechs: Vec::new(),
        }
    }
}

pub struct StaticRegistry {
    plain: Plain,
}

impl Registry for StaticRegistry {
    fn new() -> Self {
        Self {
            plain: Plain,
        }
    }
}