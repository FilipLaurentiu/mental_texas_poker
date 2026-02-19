use crate::crypto::pedersen_hash::hash_array;
use crate::{CurvePoint, FE};
use crypto_bigint::rand_core::{OsRng, RngCore};
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
use lambdaworks_math::elliptic_curve::short_weierstrass::traits::IsShortWeierstrass;
use lambdaworks_math::elliptic_curve::traits::FromAffine;
use lambdaworks_math::{traits::ByteConversion, unsigned_integer::element::U256};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{identities::One, Zero};
use rand::{rngs::ThreadRng, Rng};
use std::ops::{Add, Div, Neg};

/// Hash to curve implementation from https://datatracker.ietf.org/doc/rfc9380/
/// 6.6.2. Simplified Shallue-van de Woestijne-Ulas Method.
/// There is no need to clear the cofactor, the Stark Curve have a prime order.
/// According to the paper, it's guarantee to always return a valid point on the curve
pub fn hash_to_stark_curve(value: FE) -> CurvePoint {
    // value generated with the Sage script from the Appendix H.1
    // with the Stark Curve parameters

    let alpha: FE = StarkCurve::a();
    let beta: FE = StarkCurve::b();
    let z = FE::from(19);

    let u = hash_array(&[
        value,
        cairo_short_string_to_fe("STARK-Curve").unwrap(),
        cairo_short_string_to_fe("BlackBox").unwrap(),
    ]);

    let tv1 = z.pow(FE::from(2).representative()) * u.pow(FE::from(4).representative())
        + z * u
        .pow(FE::from(2).representative())
        .inv()
        .unwrap_or(FE::zero());

    let x1 = if tv1 == FE::zero() {
        beta.div(z * alpha).unwrap()
    } else {
        beta.neg().div(alpha).unwrap() * (FE::one() + tv1)
    };

    let gx1 = x1.pow(FE::from(3).representative()) + alpha * x1 + beta;
    let x2 = z * u.pow(FE::from(2).representative()) * x1;
    let gx2 = x2.pow(FE::from(3).representative()) + alpha * x2 + beta;

    if let Some(sqrts) = gx1.sqrt() {
        let y = sqrts.0;
        CurvePoint::from_affine(x1, y).unwrap()
    } else {
        let y = gx2.sqrt().unwrap().0;
        if *u.to_bits_le().last().unwrap() && *value.to_bits_le().last().unwrap() {
            CurvePoint::from_affine(x2, y).unwrap()
        } else {
            CurvePoint::from_affine(x2, -y).unwrap()
        }
    }
}

#[derive(Debug)]
pub enum CairoShortStringToFEError {
    /// The string provided contains non-ASCII characters.
    NonAsciiCharacter,
    /// The string provided is longer than 31 characters.
    StringTooLong,
}

pub fn cairo_short_string_to_fe(str: &str) -> Result<FE, CairoShortStringToFEError> {
    if !str.is_ascii() {
        return Err(CairoShortStringToFEError::NonAsciiCharacter);
    }
    if str.len() > 31 {
        return Err(CairoShortStringToFEError::StringTooLong);
    }

    let ascii_bytes = str.as_bytes();

    let mut buffer = [0u8; 32];
    buffer[(32 - ascii_bytes.len())..].copy_from_slice(ascii_bytes);

    // The conversion will never fail
    Ok(FE::from_bytes_be(&buffer).unwrap())
}

pub fn get_random_fe() -> FE {
    const MODULUS: U256 =
        U256::from_hex_unchecked("800000000000011000000000000000000000000000000000000000000000001");
    let mut buffer = [0u8; 32];

    let mut rng = OsRng::default();
    rng.fill_bytes(&mut buffer);

    let random_u256 = U256::from_bytes_be(&buffer).unwrap();
    let secret_scalar = random_u256.div_rem(&MODULUS).1;

    FE::from_bytes_be(&secret_scalar.to_bytes_be()).unwrap()
}

pub fn sample_field_elem() -> FE {
    let mut rng = ThreadRng::default();
    FE::new(U256 {
        limbs: [
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ],
    })
}

pub fn get_random_fe_scalar() -> FE {
    const CURVE_ORDER: U256 =
        U256::from_hex_unchecked("800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f");
    let mut buffer = [0u8; 32];

    let mut rng = ThreadRng::default();
    rng.fill_bytes(&mut buffer);

    let random_u256 = U256::from_bytes_be(buffer.as_slice()).unwrap();
    let secret_scalar = random_u256.div_rem(&CURVE_ORDER).1;

    FE::from_bytes_be(&secret_scalar.to_bytes_be()).unwrap()
}

pub fn modulo(element: &FE, modulo: &FE) -> FE {
    let (_, r) = element.representative().div_rem(&modulo.representative());
    FE::from(&r)
}

pub fn add_mod(augend: &FE, addend: &FE, modulus: &FE) -> FE {
    let augend = augend.to_big_uint();
    let addend = addend.to_big_uint();
    let modulus_bigint = modulus.to_big_uint();

    let res = augend.add(addend) % modulus_bigint;

    FE::from_bytes_be(&big_uint_to_32_bytes(&res)).unwrap()
}

pub fn mul_mod(lhs: &FE, rhs: &FE, modulus: &FE) -> FE {
    let res = (lhs.to_big_uint() * rhs.to_big_uint()) % modulus.to_big_uint();
    FE::from_bytes_be(&big_uint_to_32_bytes(&res)).unwrap()
}

fn big_uint_to_32_bytes(n: &BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_be();

    assert!(bytes.len() <= 32, "Number does not fit in 32 bytes");

    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    padded
}

pub(crate) fn inv_mod(operand: &FE, modulus: &FE) -> Option<FE> {
    let operand = BigInt::from_bytes_be(num_bigint::Sign::Plus, &operand.to_bytes_be());
    let modulus = BigInt::from_bytes_be(num_bigint::Sign::Plus, &modulus.to_bytes_be());

    let extended_gcd = operand.extended_gcd(&modulus);
    if extended_gcd.gcd != BigInt::one() {
        return None;
    }
    let result = if extended_gcd.x < BigInt::zero() {
        extended_gcd.x + modulus
    } else {
        extended_gcd.x
    };

    let (_, buffer) = result.to_bytes_be();
    let mut result = [0u8; 32];
    result[(32 - buffer.len())..].copy_from_slice(&buffer[..]);

    Some(FE::from_bytes_be(&result).unwrap())
}
