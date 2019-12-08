use std::fmt;
use std::fmt::{Display, Formatter};

/// Error type for `rsa-der`.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Indicates that a DER decoding error occurred.
    InvalidDer(simple_asn1::ASN1DecodeErr),
    /// Indicates that the RSA bitstring was not found.
    BitStringNotFound,
    /// Indicates that the RSA ASN.1 sequence was not found.
    SequenceNotFound,
    /// Indicates that the RSA modulus value was not found.
    ModulusNotFound,
    /// Indicates that the RSA exponent value was not found.
    ExponentNotFound,
    /// Indicates that the RSA private key prime P was not found.
    Prime1NotFound,
    /// Indicates that the RSA private key prime Q was not found.
    Prime2NotFound,
    /// Indicates that the RSA ASN.1 sequence did not contain exactly two values (one
    /// for `n` and one for `e`).
    InvalidSequenceLength,
}

/// Result type for `rsa-der`. This type
/// is equivalent to `std::result::Result<T, rsa_der::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Error::InvalidDer(e) => e.fmt(f)?,
            Error::BitStringNotFound => f.write_str("RSA bit string not found in ASN.1 blocks")?,
            Error::SequenceNotFound => f.write_str("ASN.1 sequence not found")?,
            Error::ModulusNotFound => f.write_str("ASN.1 public key modulus not found")?,
            Error::ExponentNotFound => f.write_str("ASN.1 public key exponent not found")?,
            Error::Prime1NotFound | Error::Prime2NotFound => {
                f.write_str("ASN.1 private key missing prime number")?
            }
            Error::InvalidSequenceLength => {
                f.write_str("ASN.1 sequence did not contain exactly two values")?
            }
        }

        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::InvalidDer(e) => Some(e),
            _ => None,
        }
    }
}
