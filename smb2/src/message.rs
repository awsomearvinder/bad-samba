use nom::bytes::complete as bytes;
use nom::error::context;
use nom::Parser;

mod header;
pub use header::SmbMessageHeader;
pub use header::SmbMessageHeaderVariant;

mod negotiate;
pub use negotiate::SmbNegotiate;

pub use negotiate::SmbNegotiateResponse;

#[derive(Debug)]
pub struct SmbMessage {
    pub header: SmbMessageHeader,
    pub body: SmbBody,
}

#[derive(Debug)]
pub enum SmbBody {
    Negotiate(SmbNegotiate),
    NegotiateResponse(SmbNegotiateResponse),
}

impl SmbBody {
    fn to_vec(self) -> Vec<u8> {
        match self {
            SmbBody::NegotiateResponse(b) => b.to_vec(),
            SmbBody::Negotiate(_) => todo!(),
        }
    }
}

impl SmbMessage {
    pub fn try_parse(body: &[u8]) -> nom::IResult<&[u8], Self, nom::error::Error<&[u8]>> {
        let (remaining, header) = SmbMessageHeader::try_parse(body)?;
        let (remaining, body) = match header.command {
            0x0 => {
                let (remaining, negotiate) = SmbNegotiate::parse(&remaining)?;
                (remaining, SmbBody::Negotiate(negotiate))
            }

            _ => todo! {},
        };
        Ok((remaining, Self { header, body }))
    }
    pub fn to_vec(self) -> Vec<u8> {
        let mut header = self.header.to_vec();
        let mut body = self.body.to_vec();
        let mut out = Vec::with_capacity(header.len() + body.len());
        out.extend(header);
        out.extend(body);
        out
    }
}

fn get_u16_le(body: &[u8]) -> nom::IResult<&[u8], u16, nom::error::Error<&[u8]>> {
    bytes::take(2usize)
        .map(|number: &[u8]| u16::from_le_bytes(number.try_into().unwrap()))
        .parse(body)
}
fn get_u32_le(body: &[u8]) -> nom::IResult<&[u8], u32, nom::error::Error<&[u8]>> {
    bytes::take(4usize)
        .map(|number: &[u8]| u32::from_le_bytes(number.try_into().unwrap()))
        .parse(body)
}
fn get_u64_le(body: &[u8]) -> nom::IResult<&[u8], u64, nom::error::Error<&[u8]>> {
    bytes::take(8usize)
        .map(|number: &[u8]| u64::from_le_bytes(number.try_into().unwrap()))
        .parse(body)
}
fn get_u128_le(body: &[u8]) -> nom::IResult<&[u8], u128, nom::error::Error<&[u8]>> {
    bytes::take(16usize)
        .map(|number: &[u8]| u128::from_le_bytes(number.try_into().unwrap()))
        .parse(body)
}

fn c_u16<'a>(
    ctx: &'static str,
    body: &'a [u8],
) -> nom::IResult<&'a [u8], u16, nom::error::Error<&'a [u8]>> {
    context(ctx, get_u16_le)(body)
}
fn c_u32<'a>(
    ctx: &'static str,
    body: &'a [u8],
) -> nom::IResult<&'a [u8], u32, nom::error::Error<&'a [u8]>> {
    context(ctx, get_u32_le)(body)
}
fn c_u64<'a>(
    ctx: &'static str,
    body: &'a [u8],
) -> nom::IResult<&'a [u8], u64, nom::error::Error<&'a [u8]>> {
    context(ctx, get_u64_le)(body)
}
fn c_u128<'a>(
    ctx: &'static str,
    body: &'a [u8],
) -> nom::IResult<&'a [u8], u128, nom::error::Error<&'a [u8]>> {
    context(ctx, get_u128_le)(body)
}
