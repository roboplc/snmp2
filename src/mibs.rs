pub use snmptools::Config;

use crate::{Oid, Result};

#[inline]
pub fn init(config: &Config) -> Result<()> {
    snmptools::init(config).map_err(|e| crate::Error::Mib(e.to_string()))
}

pub trait MibConversion {
    fn mib_name(&self) -> Result<String>;
    fn from_mib_name(name: &str) -> Result<Self>
    where
        Self: Sized;
    fn asn_type(&self) -> Result<u8>;
}

impl MibConversion for Oid<'_> {
    fn mib_name(&self) -> Result<String> {
        snmptools::get_name(self).map_err(|e| crate::Error::Mib(e.to_string()))
    }

    fn from_mib_name(name: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(snmptools::get_oid(name)
            .map_err(move |e| crate::Error::Mib(e.to_string()))?
            .to_owned())
    }

    fn asn_type(&self) -> Result<u8> {
        let val = snmptools::get_type(self).map_err(|e| crate::Error::Mib(e.to_string()))?;
        if val == 255 {
            return Err(crate::Error::Mib(
                format! {"netsnmp:mib_to_asn_type returned 255 (not found) for {self}"},
            ));
        }
        Ok(val)
    }
}
