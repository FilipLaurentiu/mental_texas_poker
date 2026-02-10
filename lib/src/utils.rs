use starknet::{
    core::{
        types::{Felt, NonZeroFelt},
        utils::cairo_short_string_to_felt,
    },
    macros::felt_dec,
};
use starknet_crypto::{PoseidonHasher, poseidon_hash};
use starknet_curve::curve_params::{ALPHA, BETA, EC_ORDER};
use starknet_types_core::curve::AffinePoint;
use std::ops::{Mul, Neg};
use crypto_bigint::rand_core::{OsRng, RngCore};
use num_bigint::BigInt;



/// Hash to curve implementation from https://datatracker.ietf.org/doc/rfc9380/
/// 6.6.2. Simplified Shallue-van de Woestijne-Ulas Method.
/// There is no need to clear the cofactor, the Stark Curve have a prime order.
/// According to the paper, it's guarantee to always return a valid point on the curve
pub fn hash_to_stark_curve(value: Felt, network: Option<Felt>) -> AffinePoint {
    // value generated with the Sage script from the Appendix H.1
    // with the Stark Curve parameters
    let z: Felt = felt_dec!("19");

    let mut poseidon_hasher = PoseidonHasher::new();
    poseidon_hasher.update(value);
    poseidon_hasher.update(cairo_short_string_to_felt("STARK-Curve").unwrap());
    poseidon_hasher.update(cairo_short_string_to_felt("BlackBox").unwrap());
    if let Some(network) = network {
        poseidon_hasher.update(network);
    }
    let u = poseidon_hasher.finalize();

    let tv1 = (z.pow_felt(&Felt::TWO) * u.pow_felt(&felt_dec!("4")) + z * u.pow_felt(&Felt::TWO))
        .inverse()
        .unwrap_or(Felt::ZERO);

    let x1 = if tv1 == Felt::ZERO {
        BETA.div_rem(&NonZeroFelt::from_felt_unchecked(z * ALPHA)).0
    } else {
        BETA.neg()
            .div_rem(&NonZeroFelt::from_felt_unchecked(ALPHA))
            .0
            * (Felt::ONE + tv1)
    };

    let gx1 = x1.pow_felt(&Felt::THREE) + ALPHA * x1 + BETA;
    let x2 = z * u.pow_felt(&Felt::TWO) * x1;
    let gx2 = x2.pow_felt(&Felt::THREE) + ALPHA * x2 + BETA;

    let gx1_sqrt = gx1.sqrt();
    if gx1_sqrt.is_some() {
        AffinePoint::new(x1, gx1.sqrt().unwrap()).unwrap()
    } else {
        let y = gx2.sqrt().unwrap();
        if *u.to_bits_le().last().unwrap() && *value.to_bits_le().last().unwrap() {
            AffinePoint::new(x2, y).unwrap()
        } else {
            AffinePoint::new(x2, -y).unwrap()
        }
    }
}

pub fn get_random_felt() -> Felt {
    let mut buffer = [0u8; 32];


    let mut rng = OsRng::default();
    rng.fill_bytes(&mut buffer);

    let res = Felt::from_bytes_be(&buffer);
    println!("Random felt {}", res);
    res
}

pub fn get_random_stark_scalar() -> Felt {
    let scalar = get_random_felt()
        .div_rem(&NonZeroFelt::from_felt_unchecked(EC_ORDER))
        .1;

    println!("Random scalar {}", scalar);
    scalar
}

pub(crate) fn mul_mod_floor(multiplicand: &Felt, multiplier: &Felt, modulus: &Felt) -> Felt {
    let multiplicand = BigInt::from_bytes_be(num_bigint::Sign::Plus, &multiplicand.to_bytes_be());
    bigint_mul_mod_floor(multiplicand, multiplier, modulus)
}

pub(crate) fn bigint_mul_mod_floor(
    multiplicand: BigInt,
    multiplier: &Felt,
    modulus: &Felt,
) -> Felt {
    let multiplier = BigInt::from_bytes_be(num_bigint::Sign::Plus, &multiplier.to_bytes_be());
    let modulus = BigInt::from_bytes_be(num_bigint::Sign::Plus, &modulus.to_bytes_be());

    let result = multiplicand.mul(multiplier) % modulus;

    let (_, buffer) = result.to_bytes_be();
    let mut result = [0u8; 32];
    result[(32 - buffer.len())..].copy_from_slice(&buffer[..]);

    Felt::from_bytes_be(&result)
}
