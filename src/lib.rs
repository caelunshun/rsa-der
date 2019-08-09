#![forbid(unsafe_code, missing_docs, missing_debug_implementations, warnings)]

//! A simple crate to convert public RSA keys to DER encoding.
//!
//! Public keys are passed to this crate simply use the `n` and  `e`
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
}
