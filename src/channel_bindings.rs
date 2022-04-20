
pub trait ChannelBindingCallback {
    fn get_cb_data(&self, cbname: &str) -> Option<&[u8]>;
}
