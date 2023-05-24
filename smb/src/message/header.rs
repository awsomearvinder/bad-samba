use nom::bytes::complete as bytes;
use nom::error::context;

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
    pub message_id: u32,
    pub async_id: Option<std::num::NonZeroU32>,
    /// Not useful for async
    pub tree_id: u32,
    pub session_id: u32,
    pub signature: u32,
}

impl SmbMessageHeader {
    pub fn try_parse(
        body: &[u8],
    ) -> nom::IResult<&[u8], SmbMessageHeader, nom::error::Error<&[u8]>> {
        use super::{c_u16, c_u32};

        let (remaining, protocol_id) = c_u32("Failed to get protocol id", body)?;
        let (remaining, header_size) = c_u16("Failed to get message header size", remaining)?;
        let (remaining, credit_charge) = c_u16("Failed to get credit charge", remaining)?;
        let (remaining, status) =
            c_u32("Failed to get (ChannelSequence,Reserved)/Charge", remaining)?;
        let (remaining, command) = c_u16("Failed to get command", remaining)?;
        let (remaining, credit_request_response) =
            c_u16("Failed to get credit request/response", remaining)?;
        let (remaining, flags) = c_u32("Failed to get credit header flags", remaining)?;
        let (remaining, next_command) = c_u32("Failed to get next command", remaining)?;
        let (remaining, message_id) = c_u32("Failed to get message id", remaining)?;
        let (remaining, _) = c_u32("Failed to get padding", remaining)?;
        let (remaining, async_id) = c_u32("Failed to get async id / reserved", remaining)?;
        let (remaining, tree_id) = c_u32("Failed to get tree id / reserved", remaining)?;
        let (remaining, session_id) = c_u32("Failed to get session id", remaining)?;
        let (remaining, _) = c_u32("Failed to get padding", remaining)?;
        let (remaining, signature) = c_u32("Failed to get signature", remaining)?;
        let (remaining, _) =
            context("Failed to get header end padding", bytes::take(12usize))(remaining)?;

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
                async_id: std::num::NonZeroU32::new(async_id),
                tree_id,
                session_id,
                signature,
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
    fn no_async_id() {
        let header = [0; 64];
        assert_eq!(
            SmbMessageHeader::try_parse(&header).unwrap().1.async_id,
            None
        );
    }
    #[test]
    fn valid_async_id() {
        let mut header = [0; 64];
        header[32] = 0xFF;
        assert_eq!(
            SmbMessageHeader::try_parse(&header).unwrap().1.async_id,
            std::num::NonZeroU32::new(u32::from_le_bytes([0xFF, 0, 0, 0]))
        );
    }
}
