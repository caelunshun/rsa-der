#![forbid(unsafe_code, missing_docs, missing_debug_implementations, warnings)]
#![doc(html_root_url = "https://docs.rs/rsa-der/0.2.0")]

//! A simple crate to encode and decode DER-formatted public and private RSA keys.
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
//! # let mut rng = OsRng;
//! # let key = RSAPrivateKey::new(&mut rng, 2048).unwrap();
//! # key
//! # }
//!
//! let key = generate_key();
//! let der_bytes = rsa_der::public_key_to_der(&key.n().to_bytes_be(), &key.e().to_bytes_be());
//! ```

use simple_asn1::{oid, ASN1Block, BigInt, BigUint, OID};

mod errors;
pub use crate::errors::*;

/// Encodes an RSA public key to DER bytes, as specified
/// by the PKCS#8 format.
///
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
/// let mut rng = OsRng;
/// let key = RSAPrivateKey::new(&mut rng, 2048).unwrap();
///
/// let der_bytes = public_key_to_der(&key.n().to_bytes_be(), &key.e().to_bytes_be());
/// ```
pub fn public_key_to_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut root_sequence = Vec::<ASN1Block>::with_capacity(4);

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

/// Encodes an RSA private / secret key to DER bytes, as specified
/// by the PKCS#8 format.
///
/// The `n`, `e` parameters are the big-endian modulus
/// and exponent of the public key, respectively, `d` is the private key exponent. Simple
/// `u8` slices are used to allow usage of this function
/// in conjunction with any crypto library.
///
/// The ASN1 DER layout is as follows:
/// ```asn1
/// RSAPrivateKey ::= SEQUENCE {
///   version           Version,
///   modulus           INTEGER,  -- n
///   publicExponent    INTEGER,  -- e
///   privateExponent   INTEGER,  -- d
///   prime1            INTEGER,  -- p
///   prime2            INTEGER,  -- q
///   exponent1         INTEGER,  -- d mod (p-1)
///   exponent2         INTEGER,  -- d mod (q-1)
///   coefficient       INTEGER,  -- (inverse of q) mod p
///   otherPrimeInfos   OtherPrimeInfos OPTIONAL
/// }
/// ```
///
/// # Examples
/// Encoding a RSA private key generated using the [`rsa`](https://docs.rs/rsa)
/// crate:
/// ```
/// use rand::rngs::OsRng;
/// use rsa_der::private_key_to_der;
/// use rsa::{RSAPrivateKey, PublicKey};
///
/// let mut rng = OsRng;
/// let key = RSAPrivateKey::new(&mut rng, 2048).unwrap();
///
/// let der_bytes = private_key_to_der(&key.n().to_bytes_be(), &key.e().to_bytes_be(), &key.d().to_bytes_be(), &key.primes()[0].to_bytes_be(), &key.primes()[1].to_bytes_be());
/// ```
pub fn private_key_to_der(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8]) -> Vec<u8> {
    let d = BigInt::from_signed_bytes_be(d);
    let p = BigInt::from_signed_bytes_be(p);
    let q = BigInt::from_signed_bytes_be(q);
    let p_minus_1: BigInt = p.clone() - 1;
    let d_mod_p_minus_1 = d.clone() % &p_minus_1;
    let q_minus_1: BigInt = q.clone() - 1;
    let d_mod_q_minus_1 = d.clone() % &q_minus_1;
    let coefficient = BigInt::from(0u8);

    let version = ASN1Block::Integer(0, BigInt::from(0u8));
    let n_block = ASN1Block::Integer(0, BigInt::from_signed_bytes_be(n));
    let e_block = ASN1Block::Integer(0, BigInt::from_signed_bytes_be(e));
    let d_block = ASN1Block::Integer(0, d);
    let p_block = ASN1Block::Integer(0, p);
    let q_block = ASN1Block::Integer(0, q);
    let d_mod_p_minus_1_block = ASN1Block::Integer(0, d_mod_p_minus_1);
    let d_mod_q_minus_1_block = ASN1Block::Integer(0, d_mod_q_minus_1);
    let coefficient = ASN1Block::Integer(0, coefficient); // FIXME TODO

    simple_asn1::to_der(&ASN1Block::Sequence(
        0,
        vec![
            version,
            n_block,
            e_block,
            d_block,
            p_block,
            q_block,
            d_mod_p_minus_1_block,
            d_mod_q_minus_1_block,
            coefficient,
        ],
    )).unwrap()
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
            if blocks.len() != 2 {
                return Err(Error::InvalidSequenceLength);
            }

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
/// use rsa::RSAPrivateKey;
/// use num_bigint_dig::BigUint;
///
/// # fn get_der_bytes() -> &'static [u8] { &[0] }
/// let bytes: &[u8] = get_der_bytes();
///
/// let (n, e, d, p, q) = rsa_der::private_key_from_der(bytes)?;
///
/// let key = RSAPrivateKey::from_components(
///                 BigUint::from_bytes_be(&n),
///                 BigUint::from_bytes_be(&e),
///                 BigUint::from_bytes_be(&d),
///                 vec![
///                        BigUint::from_bytes_be(&p),
///                        BigUint::from_bytes_be(&q)
///                 ]);
/// # Ok(())
/// # }
/// ```
pub fn private_key_from_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).map_err(Error::InvalidDer)?;

    for block in blocks {
        match block {
            ASN1Block::Sequence(_, blocks) => {
                println!("inner blocks: {}", blocks.len());
                if blocks.len() != 9 {
                    return Err(Error::InvalidSequenceLength);
                }

                let n = match &blocks[1] {
                    ASN1Block::Integer(_, n) => n,
                    _ => return Err(Error::ModulusNotFound),
                };

                let e = match &blocks[2] {
                    ASN1Block::Integer(_, e) => e,
                    _ => return Err(Error::ExponentNotFound),
                };

                let d = match &blocks[3] {
                    ASN1Block::Integer(_, d) => d,
                    _ => return Err(Error::ModulusNotFound),
                };

                let p = match &blocks[4] {
                    ASN1Block::Integer(_, p) => p,
                    _ => return Err(Error::Prime1NotFound),
                };
                let q = match &blocks[5] {
                    ASN1Block::Integer(_, q) => q,
                    _ => return Err(Error::Prime2NotFound),
                };

                // (n, e, d, p, q)
                return Ok((
                    n.to_bytes_be().1,
                    e.to_bytes_be().1,
                    d.to_bytes_be().1,
                    p.to_bytes_be().1,
                    q.to_bytes_be().1,
                ));
            }
            _ => {}
        };
    }
    Err(Error::SequenceNotFound)
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

    #[test]
    fn test_private_key_from_der() {
        let key = Rsa::generate(2048).unwrap();

        let der = key.private_key_to_der().unwrap();

        let (n, e, d, p, q) = private_key_from_der(&der).unwrap();

        assert_eq!(key.p().unwrap().to_vec(), p);
        assert_eq!(key.q().unwrap().to_vec(), q);
        assert_eq!(key.n().to_vec(), n);
        assert_eq!(key.e().to_vec(), e);
        assert_eq!(key.d().to_vec(), d);
        // assert_eq!(key.dmp1().unwrap().to_vec(), dmp1);
        // assert_eq!(key.dmq1().unwrap().to_vec(), dmq1);
    }

    #[test]
    fn test_private_key_to_der() {
        let key = Rsa::generate(2048).unwrap();

        let bytes = private_key_to_der(
            &key.n().to_vec(),
            &key.e().to_vec(),
            &key.d().to_vec(),
            &key.p().unwrap().to_vec(),
            &key.q().unwrap().to_vec(),
        );

        // Confirm that converting back works correctly
        let new_key = Rsa::private_key_from_der(&bytes).unwrap();

        assert_eq!(key.n(), new_key.n());
        assert_eq!(key.e(), new_key.e());
        assert_eq!(key.q().unwrap(), new_key.q().unwrap());
        assert_eq!(key.p().unwrap(), new_key.p().unwrap());

        use num_bigint_dig;

        let reconstructed = rsa::RSAPrivateKey::from_components(
            num_bigint_dig::BigUint::from_bytes_be(key.n().to_vec().as_slice()),
            num_bigint_dig::BigUint::from_bytes_be(key.e().to_vec().as_slice()),
            num_bigint_dig::BigUint::from_bytes_be(key.d().to_vec().as_slice()),
            vec![
                num_bigint_dig::BigUint::from_bytes_be(key.p().unwrap().to_vec().as_slice()),
                num_bigint_dig::BigUint::from_bytes_be(key.q().unwrap().to_vec().as_slice())
            ]
        );
        assert!(reconstructed.validate().is_ok());
    }
}
