use nom::{
    bytes::complete::take,
    combinator::{map, verify},
    error::context,
    multi::count,
    Parser,
};

use crate::message::{c_u128, c_u16, c_u32};

use self::negotiate_context::SmbNegotiateContext;

mod negotiate_context;

#[derive(Debug, PartialEq)]
pub struct SmbNegotiate {
    // size is always 36, because for some reason
    // we don't include the dialect.
    pub size: u16,
    pub dialect_count: u16,
    pub security_mode: SmbSecurityMode,
    pub capabilities: u32,
    pub client_guid: u128,
    pub dependant_field: DialectDependantField,
    pub dialects: Vec<u16>,
    pub negotiate_context_list: Option<Vec<SmbNegotiateContext>>,
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq)]
pub enum SmbSecurityMode {
    SigningEnabled = 0x01,
    SigningRequired = 0x02,
}

#[derive(Debug)]
pub struct OutOfRange;

impl TryFrom<u16> for SmbSecurityMode {
    type Error = OutOfRange;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::SigningEnabled),
            0x02 => Ok(Self::SigningRequired),
            _ => Err(OutOfRange),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DialectDependantField {
    NegContext { offset: u32, count: u16 },
    ClientStartTime(u64),
}

impl SmbNegotiate {
    pub fn parse(body: &[u8]) -> nom::IResult<&[u8], SmbNegotiate, nom::error::Error<&[u8]>> {
        let (remaining, structure_size) = c_u16("Failed to get structure size", body)?;
        let (remaining, dialect_count) = c_u16("Failed to get dialect count", remaining)?;
        let (remaining, security_mode) = context(
            "Failed to get security mode",
            verify(
                take(2usize).map(|bytes: &[u8]| u16::from_le_bytes(bytes.try_into().unwrap())),
                |&i| (0x01..=0x02).contains(dbg! {&i}),
            ),
        )(remaining)?;
        let security_mode = SmbSecurityMode::try_from(security_mode).unwrap();
        let (remaining, _) = c_u16("Failed to get padding", remaining)?;
        let (remaining, capabilities) = c_u32("Failed to get capabilities", remaining)?;
        let (remaining, client_guid) = c_u128("Failed to get client_guid", remaining)?;
        // either client_start_time or context offset, context count.
        // depends on dialects, parse this later
        let (remaining, dependant_field) = take(8usize)(remaining)?;

        let (_variable_padding, dialects) = context(
            "Failed to grab {dialect_count} dialects",
            count(
                take(2usize).map(|bytes: &[u8]| u16::from_le_bytes(bytes.try_into().unwrap())),
                dialect_count as _,
            ),
        )(remaining)?;

        let dependant_field = if dialects.contains(&0x0311) {
            let (remaining, offset) = map(take(4usize), |bytes: &[u8]| {
                u32::from_le_bytes(bytes.try_into().unwrap())
            })(dependant_field)?;
            let (_padding, count) = map(take(2usize), |bytes: &[u8]| {
                u16::from_le_bytes(bytes.try_into().unwrap())
            })(remaining)?;
            DialectDependantField::NegContext { offset, count }
        } else {
            DialectDependantField::ClientStartTime(u64::from_le_bytes(
                dependant_field.try_into().unwrap(),
            ))
        };
        let negotiate_context_list = match dependant_field {
            // sigh, this field is defined as an offset from the header.
            // hence why - 64
            DialectDependantField::NegContext { offset, count } => {
                context(
                    "Failed to parse negotiate context list",
                    nom::multi::count(negotiate_context::SmbNegotiateContext::parse, count as _),
                )
                .map(Some)
                .parse(&body[(offset as usize - 64)..])?
                .1
            }
            DialectDependantField::ClientStartTime(_) => None,
        };
        Ok((
            &[] as _,
            Self {
                size: structure_size,
                dialect_count,
                security_mode,
                capabilities,
                client_guid,
                dependant_field,
                dialects,
                negotiate_context_list,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // test inspired from example at:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c9efe8ca-ff34-44d0-bfbe-58a9b9db50d4
    #[test]
    fn example_negotiate() {
        #[rustfmt::skip]
        let smb_negotiate = [
            // size    | dialect count
            0x24, 0x00, 0x02, 0x00,
            // sec mode| reserved
            0x01, 0x00, 0x00, 0x00,
            // capabilities
            0x00, 0x00, 0x00, 0x00,
            // guid
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // client start time
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // dialects
            0x02, 0x02, 0x03, 0x01
        ];

        assert_eq!(
            SmbNegotiate::parse(&smb_negotiate),
            Ok((
                &[] as _,
                SmbNegotiate {
                    size: 0x24,
                    dialect_count: 0x02,
                    security_mode: SmbSecurityMode::SigningEnabled,
                    capabilities: 0,
                    client_guid: 1,
                    dependant_field: DialectDependantField::ClientStartTime(0),
                    dialects: vec![0x0202, 0x0103],
                    negotiate_context_list: None
                }
            ))
        )
    }
}
