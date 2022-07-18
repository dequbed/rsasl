use std::cmp::Ordering;
use std::fmt;
use crate::builder::{ConfigBuilder, WantMechanisms};
use crate::callback::SessionCallback;
use crate::registry::Mechanism;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ClientSide {}
    impl Sealed for super::ServerSide {}
}
pub trait ConfigSide: sealed::Sealed {}

impl ConfigSide for ClientSide {}
impl ConfigSide for ServerSide {}

pub struct SASLConfig<Side: ConfigSide> {
    side: Side,
    callback: Box<dyn SessionCallback>,

    filter: fn(a: &&Mechanism) -> bool,
    sorter: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,

    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
}
impl<Side: ConfigSide> fmt::Debug for SASLConfig<Side> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("SASLConfig");
        #[cfg(feature = "registry_dynamic")]
            d.field("dynamic mechanisms", &self.dynamic_mechs);
        d.finish()
    }
}

impl SASLConfig<ClientSide> {
    pub fn builder() -> ConfigBuilder<ClientSide, WantMechanisms> {
        ConfigBuilder::new(ClientSide)
    }
}
impl SASLConfig<ServerSide> {
    pub fn builder() -> ConfigBuilder<ServerSide, WantMechanisms> {
        ConfigBuilder::new(ServerSide)
    }
}
impl<Side: ConfigSide> SASLConfig<Side> {
    fn mech_list(&self) -> impl Iterator<Item = &Mechanism> {
        todo!()
    }
}

pub struct ClientSide;
pub struct ServerSide;

pub type ClientConfig = SASLConfig<ClientSide>;
pub type ServerConfig = SASLConfig<ServerSide>;