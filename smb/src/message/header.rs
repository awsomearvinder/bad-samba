use nom::bytes::complete as bytes;
use nom::Parser;

#[derive(Debug, PartialEq)]
pub struct SmbMessageHeader {
    pub protocol_id: u32,
    pub header_size: u16,
    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    pub credit_request_response: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub variant: SmbMessageHeaderVariant,
    pub session_id: u64,
    pub signature: u128,
}

#[derive(Debug, PartialEq)]
pub enum SmbMessageHeaderVariant {
    Sync { tree_id: u32 },
    Async { id: std::num::NonZeroU64 },
}

impl SmbMessageHeader {
    fn parse_variant<'a>(
        body: &'a [u8],
    ) -> nom::IResult<&[u8], SmbMessageHeaderVariant, nom::error::Error<&[u8]>> {
        let get_sync = |body: &'a [u8]| {
            // if the body starts with 4 zeros, the next 4 bytes
            // is the tree id for the sync variant.
            let (remaining, _) = bytes::tag([0; 4])(body)?;
            bytes::take(4usize)
                .map(|tree_id: &[u8]| SmbMessageHeaderVariant::Sync {
                    tree_id: u32::from_le_bytes(tree_id.try_into().unwrap()),
                })
                .parse(remaining)
        };

        let get_async = bytes::take(8usize).map(|id: &[u8]| SmbMessageHeaderVariant::Async {
            // the ID is stored in little endian byte order.
            id: std::num::NonZeroU64::new(u64::from_le_bytes(id.try_into().unwrap())).unwrap(),
        });
        // try getting the sync variant, and if it fails, try getting
        // the async
        nom::branch::alt((get_sync, get_async))(body)
    }

    pub fn try_parse(
        body: &[u8],
    ) -> nom::IResult<&[u8], SmbMessageHeader, nom::error::Error<&[u8]>> {
        use super::*;

        let (remaining, protocol_id) = c_u32("Failed to get protocol id", body)?;
        let (remaining, header_size) = nom::combinator::verify(
            |remaining| c_u16("Failed to get message header size", remaining),
            |&s| s == 64,
        )(remaining)?;
        let (remaining, credit_charge) = c_u16("Failed to get credit charge", remaining)?;
        let (remaining, status) =
            c_u32("Failed to get (ChannelSequence,Reserved)/Charge", remaining)?;
        let (remaining, command) = c_u16("Failed to get command", remaining)?;
        let (remaining, credit_request_response) =
            c_u16("Failed to get credit request/response", remaining)?;
        let (remaining, flags) = c_u32("Failed to get credit header flags", remaining)?;
        let (remaining, next_command) = c_u32("Failed to get next command", remaining)?;
        let (remaining, message_id) = c_u64("Failed to get message id", remaining)?;
        let (remaining, variant) = Self::parse_variant(remaining)?;
        let (remaining, session_id) = c_u64("Failed to get session id", remaining)?;
        let (remaining, signature) = c_u128("Failed to get signature", remaining)?;

        Ok((
            remaining,
            Self {
                protocol_id,
                header_size,
                credit_charge,
                status,
                command,
                credit_request_response,
                flags,
                next_command,
                message_id,
                session_id,
                signature,
                variant,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_protocol_id() {
        let mut header = [0; 64];
        header[0] = 0xFE;
        header[1] = b'S';
        header[2] = b'M';
        header[3] = b'B';
        assert_eq!(
            SmbMessageHeader::try_parse(&header).unwrap().1.protocol_id,
            u32::from_le_bytes([0xFE, b'S', b'M', b'B'])
        );
    }
    #[test]
    fn valid_tree_id() {
        let mut header = [0; 64];
        header[37] = 0x04;
        assert_eq!(
            SmbMessageHeader::try_parse(&header).unwrap().1.variant,
            SmbMessageHeaderVariant::Sync {
                tree_id: u32::from_le_bytes([0x00, 0x04, 0x00, 0x00])
            }
        );
    }
    #[test]
    fn valid_async_id() {
        let mut header = [0; 64];
        header[32] = 0xFF;
        assert_eq!(
            SmbMessageHeader::try_parse(&header).unwrap().1.variant,
            SmbMessageHeaderVariant::Async {
                id: std::num::NonZeroU64::new(u64::from_le_bytes([0xFF, 0, 0, 0, 0, 0, 0, 0]))
                    .unwrap()
            }
        );
    }
}
