#![forbid(unsafe_code, missing_docs, missing_debug_implementations, warnings)]
#![doc(html_root_url = "https://docs.rs/rsa-der/0.2.0")]

//! A simple crate to encode and decode DER-formatted public RSA keys.
//!
//! Public keys are passed to and returned from functions simply using the `n` and  `e`
//! components, so any RSA library can be used in conjunction with this crate.
//!
//! # Examples
//! Convert an RSA public key to DER bytes:
//! ```no_run
//! # use rsa::{RSAPrivateKey, PublicKey};
//! use rand::rngs::OsRng;
//! # fn generate_key() -> impl PublicKey {
//! # let mut rng = OsRng::new().unwrap();
//! # let key = RSAPrivateKey::new(&mut rng, 2048).unwrap();
//! # key
//! # }
//!
//! let key = generate_key();
//! let der_bytes = rsa_der::public_key_to_der(&key.n().to_bytes_be(), &key.e().to_bytes_be());
//! ```

use simple_asn1::{oid, ASN1Block, BigInt, BigUint, OID};
use std::fmt;
use std::fmt::{Display, Formatter};

/// Encodes an RSA public key to DER bytes, as specified
/// by the PKCS#8 format.
///
/// The `n` and `e` parameters are the big-endian modulus
/// and exponent of the public key, respectively. Simple
/// `u8` slices are used to allow usage of this function
/// in conjunction with any crypto library.
///
/// # Examples
/// Encoding an RSA public key generated using the [`rsa`](https://docs.rs/rsa)
/// crate:
/// ```
/// use rand::rngs::OsRng;
/// use rsa_der::public_key_to_der;
/// use rsa::{RSAPrivateKey, PublicKey};
///
/// let mut rng = OsRng::new().unwrap();
/// let key = RSAPrivateKey::new(&mut rng, 2048).unwrap();
///
/// let der_bytes = public_key_to_der(&key.n().to_bytes_be(), &key.e().to_bytes_be());
/// ```
pub fn public_key_to_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut root_sequence = vec![];

    // Weird magic number - I have no idea what this is supposed to mean.
    let oid = oid!(1, 2, 840, 113_549, 1, 1, 1);
    root_sequence.push(ASN1Block::Sequence(
        0,
        vec![ASN1Block::ObjectIdentifier(0, oid), ASN1Block::Null(0)],
    ));

    let n_block = ASN1Block::Integer(0, BigInt::from_signed_bytes_be(n));
    let e_block = ASN1Block::Integer(0, BigInt::from_signed_bytes_be(e));

    let rsa_key_bits =
        simple_asn1::to_der(&ASN1Block::Sequence(0, vec![n_block, e_block])).unwrap();

    root_sequence.push(ASN1Block::BitString(
        0,
        rsa_key_bits.len() * 8,
        rsa_key_bits,
    ));

    simple_asn1::to_der(&ASN1Block::Sequence(0, root_sequence)).unwrap()
}

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
}

type StdResult<T, E> = std::result::Result<T, E>;

/// Result type for `rsa-der`. This type
/// is equivalent to `std::result::Result<T, rsa_der::Error>`.
pub type Result<T> = StdResult<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> StdResult<(), fmt::Error> {
        match self {
            Error::InvalidDer(e) => e.fmt(f)?,
            Error::BitStringNotFound => f.write_str("RSA bit string not found in ASN.1 blocks")?,
            Error::SequenceNotFound => f.write_str("ASN.1 sequence not found")?,
            Error::ModulusNotFound => f.write_str("ASN.1 public key modulus not found")?,
            Error::ExponentNotFound => f.write_str("ASN.1 public key exponent not found")?,
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

/// Decodes a DER-encoded public key into the raw
/// `n` and `e` components.
///
/// The returned tuple is in the form `(n, e)`, where `n` and `e`
/// are both big-endian big integers representing the key modulus
/// and exponent, respectively.
///
/// # Examples
/// Parsing DER bytes into a public RSA key usable with the
/// [`rsa`](https://docs.rs/rsa/) crate:
/// ```no_run
/// # fn main() -> Result<(), rsa_der::Error> {
/// use rsa::RSAPublicKey;
/// use num_bigint_dig::BigUint;
///
/// # fn get_der_bytes() -> &'static [u8] { &[0] }
/// let bytes: &[u8] = get_der_bytes();
///
/// let (n, e) = rsa_der::public_key_from_der(bytes)?;
///
/// let key = RSAPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e));
/// # Ok(())
/// # }
/// ```
pub fn public_key_from_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).map_err(Error::InvalidDer)?;

    let mut bit_strings = Vec::with_capacity(1);
    find_bit_string(&blocks, &mut bit_strings);

    if bit_strings.is_empty() {
        return Err(Error::BitStringNotFound);
    }

    let bit_string = &bit_strings[0];

    let inner_asn = simple_asn1::from_der(bit_string).map_err(Error::InvalidDer)?;

    let (n, e) = match &inner_asn[0] {
        ASN1Block::Sequence(_, blocks) => {
            let n = match &blocks[0] {
                ASN1Block::Integer(_, n) => n,
                _ => return Err(Error::ModulusNotFound),
            };

            let e = match &blocks[1] {
                ASN1Block::Integer(_, e) => e,
                _ => return Err(Error::ExponentNotFound),
            };

            (n, e)
        }
        _ => return Err(Error::SequenceNotFound),
    };

    Ok((n.to_bytes_be().1, e.to_bytes_be().1))
}

/// Recursively through ASN1 blocks, attempting
/// to find a BitString value.
fn find_bit_string(blocks: &[ASN1Block], mut result: &mut Vec<Vec<u8>>) {
    for block in blocks.iter() {
        match block {
            ASN1Block::BitString(_, _, bytes) => result.push(bytes.to_vec()),
            ASN1Block::Sequence(_, blocks) => find_bit_string(&blocks[..], &mut result),
            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;

    #[test]
    fn test_public_key_to_der() {
        let key = Rsa::generate(2048).unwrap();

        let bytes = public_key_to_der(&key.n().to_vec(), &key.e().to_vec());

        // Confirm that converting back works correctly
        let new_key = Rsa::public_key_from_der(&bytes).unwrap();

        assert_eq!(key.n(), new_key.n());
        assert_eq!(key.e(), new_key.e());
    }

    #[test]
    fn test_public_key_from_der() {
        let key = Rsa::generate(2048).unwrap();

        let der = key.public_key_to_der().unwrap();

        let (n, e) = public_key_from_der(&der).unwrap();

        assert_eq!(key.n().to_vec(), n);
        assert_eq!(key.e().to_vec(), e);
    }
}
