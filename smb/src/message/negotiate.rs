#[derive(Debug)]
pub struct Smb1Negotiate {
    pub parameters: Smb1Parameters,
    pub smb_data: Smb1NegotiateData,
}

impl Smb1Negotiate {
    pub fn try_parse(body: &[u8]) -> nom::IResult<&[u8], Self, nom::error::Error<&[u8]>> {
        let (remaining, word_count) = nom::number::complete::le_u8(body)?;
        let (remaining, dialects) = nom::multi::length_value(
            nom::number::complete::le_u16,
            nom::multi::many0(Smb1Dialect::try_parse),
        )(remaining)?;
        Ok((
            remaining,
            Self {
                parameters: Smb1Parameters { word_count },
                smb_data: Smb1NegotiateData { dialects },
            },
        ))
    }
}

#[derive(Debug)]
pub struct Smb1Parameters {
    // not used currently.
    pub word_count: u8,
}

#[derive(Debug)]
pub struct Smb1NegotiateData {
    pub dialects: Vec<Smb1Dialect>,
}

#[derive(Debug)]
pub struct Smb1Dialect {
    pub dialect_string: Vec<u8>,
}

impl Smb1Dialect {
    fn try_parse(body: &[u8]) -> nom::IResult<&[u8], Self, nom::error::Error<&[u8]>> {
        let (remaining, _) = nom::bytes::complete::tag([0x02])(body)?;
        let (remaining, dialect_string) = nom::bytes::complete::take_till(|i| i == 0)(remaining)?;
        Ok((
            &remaining[1..], // offset for the ending NUL byte
            Self {
                dialect_string: dialect_string.to_vec(),
            },
        ))
    }
}
