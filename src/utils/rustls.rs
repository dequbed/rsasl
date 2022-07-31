use rustls::Connection;
use crate::channel_bindings::ChannelBindingCallback;

pub struct RustlsCBExporter {
    data: [u8; 32]
}

impl RustlsCBExporter {
    pub fn new(conn: &Connection) -> Result<Self, rustls::Error> {
        let mut data = [0u8;32];
        conn.export_keying_material(&mut data, b"EXPORTER-Channel-Binding", None)?;
        Ok(Self { data })
    }
}

impl ChannelBindingCallback for RustlsCBExporter {
    fn get_cb_data(&self, cbname: &str) -> Option<&[u8]> {
        if cbname == "tls-exporter" {
            Some(&self.data[..])
        } else {
            None
        }
    }
}