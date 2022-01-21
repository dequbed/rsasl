pub type ChannelBindingName = str;
pub type ChannelBindingData = [u8];

mod well_known {
    use super::ChannelBindingName;

    const TLS_UNIQUE: &'static ChannelBindingName = "tls-unique";
}