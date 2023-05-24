use nom::bytes::complete as bytes;
use nom::Parser;

mod header;
pub use header::SmbMessageHeader;

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
