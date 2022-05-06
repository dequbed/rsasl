
pub trait ChannelBindingCallback {
    fn preferred_cb_data(&self) -> Option<(&str, &[u8])>;
    fn get_cb_data(&self, cbname: &str) -> Option<&[u8]>;
}

pub struct NoChannelBindings;
impl ChannelBindingCallback for NoChannelBindings {
    fn get_cb_data(&self, _cbname: &str) -> Option<&[u8]> {
        None
    }

    fn preferred_cb_data(&self) -> Option<(&str, &[u8])> {
        None
    }
}
