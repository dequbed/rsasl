pub trait ChannelBindingCallback {
    fn get_cb_data(&self, cbname: &str) -> Option<&[u8]>;
}

#[derive(Debug)]
pub struct NoChannelBindings;
impl ChannelBindingCallback for NoChannelBindings {
    fn get_cb_data(&self, _cbname: &str) -> Option<&[u8]> {
        None
    }
}

pub struct ThisCb {
    name: &'static str,
    value: Box<[u8]>,
}
impl ThisCb {
    pub fn new(name: &'static str, value: Box<[u8]>) -> Self {
        Self { name, value }
    }
}
impl ChannelBindingCallback for ThisCb {
    fn get_cb_data(&self, cbname: &str) -> Option<&[u8]> {
        if self.name == cbname {
            Some(self.value.as_ref())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::ClientConfig;
    use crate::mechname::Mechname;
    use std::sync::Arc;

    use crate::sasl::SASLClient;

    use crate::typed::TaggedOption;
    use crate::validate::{NoValidation, Validate};

    #[test]
    #[allow(unreachable_code)]
    fn test_this_cb() {
        let cbdata = b"foobar";
        let thiscb = ThisCb::new("this-cb", cbdata.to_vec().into_boxed_slice());
        let config = ClientConfig::with_credentials(None, String::new(), String::new()).unwrap();
        let sasl = SASLClient::with_cb(Arc::new(config), thiscb);
        let session = sasl
            .start_suggested(&[&Mechname::new(b"PLAIN").unwrap()])
            .unwrap();

        let mut tagged_option = TaggedOption::<'_, NoValidation>(None);

        let validate = Validate::new::<NoValidation>(&mut tagged_option);
        session
            .get_cb_data("this-cb", validate, &mut |cb| {
                println!("got {:?}", cb);
                assert_eq!(cb, cbdata);
                Ok(())
            })
            .unwrap();

        let validate = Validate::new::<NoValidation>(&mut tagged_option);
        let e = session
            .get_cb_data("blahblubb", validate, &mut |_cb| {
                panic!("returned cbdata that should not be there!");
                Ok(())
            })
            .unwrap_err();
        assert!(e.is_missing_prop())
    }
}
