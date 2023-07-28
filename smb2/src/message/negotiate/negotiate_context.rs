use nom::bytes::complete::take;
use nom::combinator::verify;
use nom::multi::count;
use nom::Parser;

use crate::message::{get_u16_le, get_u32_le};

type Utf16String = Vec<u16>;

#[derive(Debug, PartialEq)]
pub struct SmbNegotiateContext {
    pub context_type: u16,
    pub data_length: u16,
    pub data: SmbNegotiateContextData,
}

impl SmbNegotiateContext {
    pub fn parse(
        body: &[u8],
    ) -> nom::IResult<&[u8], SmbNegotiateContext, nom::error::Error<&[u8]>> {
        let (remaining, discriminant) = verify(
            take(2usize)
                .map(|bytes: &[u8]| u16::from_le_bytes(bytes.try_into().unwrap()))
                .map(SmbNegotiateContextTypes::try_from),
            |f| f.is_ok(),
        )
        // we already verified it.
        .map(|f| f.unwrap())
        .parse(body)?;

        let (remaining, data_length) = get_u16_le(remaining)?;
        use SmbNegotiateContextTypes::*;
        let (remaining, context) = match discriminant {
            PreauthIntegrityCapabilies => {
                let (remaining, hash_algo_count) = get_u16_le(remaining)?;
                let (remaining, salt_length) = get_u16_le(remaining)?;
                let (remaining, hash_algorithms) = count(take(2usize), hash_algo_count as _)
                    .map(|algos| {
                        algos
                            .into_iter()
                            .map(|i: &[_]| u16::from_le_bytes(i.try_into().unwrap()))
                    })
                    .parse(remaining)?;
                let (remaining, salt) = take(salt_length)(remaining)?;
                (
                    remaining,
                    SmbNegotiateContextData::PreauthIntegrityCapabilities {
                        hash_algo_count,
                        salt_length,
                        hash_algo: hash_algorithms.collect(),
                        salt: salt.to_vec(),
                    },
                )
            }
            EncryptionCapabilities => {
                let (remaining, cipher_count) = get_u16_le(remaining)?;
                let (_, ciphers) = count(take(2usize), cipher_count as usize)
                    .map(|ciphers| {
                        ciphers
                            .into_iter()
                            .map(|i: &[_]| u16::from_le_bytes(i.try_into().unwrap()))
                    })
                    .parse(remaining)?;

                (
                    remaining,
                    SmbNegotiateContextData::EncryptionCapabilities {
                        cipher_count,
                        ciphers: ciphers.collect(),
                    },
                )
            }
            CompressionCapabilities => {
                let (remaining, compression_algo_count) = get_u16_le(remaining)?;
                let (remaining, _padding) = get_u16_le(remaining)?;
                let (remaining, flags) = get_u32_le(remaining)?;
                let (_, compression_algos) = count(take(2usize), compression_algo_count as usize)
                    .map(|compression_algos| {
                        compression_algos
                            .into_iter()
                            .map(|i: &[_]| u16::from_le_bytes(i.try_into().unwrap()))
                    })
                    .parse(remaining)?;
                (
                    remaining,
                    SmbNegotiateContextData::CompressionCapabilities {
                        compression_algo_count,
                        flags,
                        compression_algos: compression_algos.collect(),
                    },
                )
            }
            NetNameNegotiateContextId => {
                let (_, net_name) = nom::multi::many0(take(2usize))
                    .map(|code_points| {
                        code_points.into_iter().map(|code_point: &[u8]| {
                            u16::from_le_bytes(code_point.try_into().unwrap())
                        })
                    })
                    .parse(remaining)?;
                (
                    remaining,
                    SmbNegotiateContextData::NetNameNegotiateContextId {
                        net_name: net_name.collect(),
                    },
                )
            }
            TransportCapabilities => {
                let (remaining, flags) = get_u32_le(remaining)?;
                (
                    remaining,
                    SmbNegotiateContextData::TransportCapabilities { flags },
                )
            }
            RdmaTranformCapabilities => {
                let (remaining, transform_count) = get_u16_le(remaining)?;
                let (remaining, _reserved) = take(6usize)(remaining)?;
                let (_, transform_ids) = count(take(2usize), transform_count as usize)
                    .map(|ids| {
                        ids.into_iter()
                            .map(|id: &[_]| u16::from_le_bytes(id.try_into().unwrap()))
                    })
                    .parse(remaining)?;
                (
                    remaining,
                    SmbNegotiateContextData::RdmaTransformCapabilities {
                        transform_count,
                        transform_ids: transform_ids.collect(),
                    },
                )
            }
            SigningCapabilities => {
                let (remaining, signing_algo_count) = get_u16_le(remaining)?;
                let (_, algos) = count(take(2usize), signing_algo_count as usize)
                    .map(|algos| {
                        algos
                            .into_iter()
                            .map(|algo: &[_]| u16::from_le_bytes(algo.try_into().unwrap()))
                    })
                    .parse(remaining)?;
                (
                    remaining,
                    SmbNegotiateContextData::SigningCapabilities {
                        signing_algo_count,
                        signing_algos: algos.collect(),
                    },
                )
            }
        };
        Ok((
            remaining,
            SmbNegotiateContext {
                context_type: discriminant as u16,
                data_length,
                data: context,
            },
        ))
    }
}

// In reality, this isn't actually that efficient,
// as this could just be used as the discriminator for
// SmbNegotiateContext, and we could forego this entire enum all together.
// I don't know if rust supports custom discriminators for non-C like enums,
// though. And it'd be unsafe to do.
#[repr(u16)]
enum SmbNegotiateContextTypes {
    PreauthIntegrityCapabilies = 1,
    EncryptionCapabilities = 2,
    CompressionCapabilities = 3,
    NetNameNegotiateContextId = 5,
    TransportCapabilities = 6,
    RdmaTranformCapabilities = 7,
    SigningCapabilities = 8,
}

#[derive(Debug)]
struct InvalidType;

impl TryFrom<u16> for SmbNegotiateContextTypes {
    type Error = InvalidType;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::PreauthIntegrityCapabilies),
            2 => Ok(Self::EncryptionCapabilities),
            3 => Ok(Self::CompressionCapabilities),
            5 => Ok(Self::NetNameNegotiateContextId),
            6 => Ok(Self::TransportCapabilities),
            7 => Ok(Self::RdmaTranformCapabilities),
            8 => Ok(Self::SigningCapabilities),
            _ => Err(InvalidType),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SmbNegotiateContextData {
    PreauthIntegrityCapabilities {
        hash_algo_count: u16,
        salt_length: u16,
        hash_algo: Vec<u16>,
        salt: Vec<u8>,
    },
    EncryptionCapabilities {
        cipher_count: u16,
        ciphers: Vec<u16>,
    },
    CompressionCapabilities {
        compression_algo_count: u16,
        flags: u32,
        compression_algos: Vec<u16>,
    },
    NetNameNegotiateContextId {
        // sigh, UTF-16 encoded. User can deal with it
        // how they want, I won't decode for u.
        // I'll be nice and strip off the NULL byte though.
        net_name: Utf16String,
    },
    TransportCapabilities {
        flags: u32,
    },
    RdmaTransformCapabilities {
        transform_count: u16,
        transform_ids: Vec<u16>,
    },
    SigningCapabilities {
        signing_algo_count: u16,
        signing_algos: Vec<u16>,
    },
}
