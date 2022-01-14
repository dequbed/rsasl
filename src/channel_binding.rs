


pub trait ChannelBindingsCB {
    fn provide_cb(&self, _channel_binding: &str) -> Option<&[u8]> {
        None
    }
}

pub struct NoChannelBindings;
impl ChannelBindingsCB for NoChannelBindings {}