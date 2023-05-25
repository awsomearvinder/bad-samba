#[derive(Debug, PartialEq)]
pub struct SmbNegotiateContext {
    pub context_type: u16,
    pub data_length: u16,
    pub data: SmbNegotiateContextData,
}

impl SmbNegotiateContext {}

#[derive(Debug, PartialEq)]
pub enum SmbNegotiateContextData {}

pub fn parse_neg_context(
    _body: &[u8],
) -> nom::IResult<&[u8], SmbNegotiateContext, nom::error::Error<&[u8]>> {
    todo! {}
}
