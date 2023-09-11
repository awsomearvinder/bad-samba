pub mod message;

#[derive(Debug)]
pub struct Smb1Message {
    pub header: Smb1Header,
    pub body: Smb1Body,
}

impl Smb1Message {
    pub fn try_parse(body: &[u8]) -> nom::IResult<&[u8], Smb1Message, nom::error::Error<&[u8]>> {
        let (remaining, header) = Smb1Header::try_parse(body)?;
        let (remaining, body) = match header.command {
            0x72 => {
                let (remaining, body) = message::Smb1Negotiate::try_parse(remaining)?;
                (remaining, Smb1Body::SmbComNegotiate(body))
            }
            _ => panic!("Unsupported op!"), // todo, don't panic.
        };
        Ok((remaining, Self { header, body }))
    }
}

#[derive(Debug)]
pub struct Smb1Header {
    pub protocol: [u8; 4],
    pub command: u8,
    pub status: u32,
    pub flags: u8,
    pub flags2: u16,
    pub pid_high: u16,
    pub security_features: [u8; 8],
    pub tid: [u8; 2],
    pub pid_low: u16,
    pub uid: [u8; 2],
    pub mid: [u8; 2],
}

impl Smb1Header {
    pub fn try_parse(body: &[u8]) -> nom::IResult<&[u8], Smb1Header, nom::error::Error<&[u8]>> {
        let (remaining, protocol) = nom::bytes::complete::tag(b"\xFFSMB")(body)?;
        let (remaining, command) = nom::bytes::complete::take(1usize)(remaining)?;
        let (remaining, status) = nom::bytes::complete::take(4usize)(remaining)?;
        let (remaining, flags) = nom::bytes::complete::take(1usize)(remaining)?;
        let (remaining, flags2) = nom::bytes::complete::take(2usize)(remaining)?;
        let (remaining, pid_high) = nom::bytes::complete::take(2usize)(remaining)?;
        let (remaining, security_features) = nom::bytes::complete::take(8usize)(remaining)?;
        let (remaining, _) = nom::bytes::complete::take(2usize)(remaining)?;
        let (remaining, tid) = nom::bytes::complete::take(2usize)(remaining)?;
        let (remaining, pid_low) = nom::bytes::complete::take(2usize)(remaining)?;
        let (remaining, uid) = nom::bytes::complete::take(2usize)(remaining)?;
        let (remaining, mid) = nom::bytes::complete::take(2usize)(remaining)?;
        Ok((
            remaining,
            Smb1Header {
                protocol: protocol.try_into().unwrap(),
                command: command[0],
                status: u32::from_le_bytes(status.try_into().unwrap()),
                flags: flags[0],
                flags2: u16::from_le_bytes(flags2.try_into().unwrap()),
                pid_high: u16::from_le_bytes(pid_high.try_into().unwrap()),
                security_features: security_features.try_into().unwrap(),
                tid: tid.try_into().unwrap(),
                pid_low: u16::from_le_bytes(pid_low.try_into().unwrap()),
                uid: uid.try_into().unwrap(),
                mid: mid.try_into().unwrap(),
            },
        ))
    }
}

#[derive(Debug)]
pub enum Smb1Body {
    SmbComNegotiate(message::Smb1Negotiate),
}
