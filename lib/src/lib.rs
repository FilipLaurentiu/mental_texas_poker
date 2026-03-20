#![allow(warnings)]

use lambdaworks_math::{
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    field::{
        element::FieldElement,
        fields::fft_friendly::stark_252_prime_field::Stark252PrimeField,
        fields::montgomery_backed_prime_fields::{IsModulus, U256PrimeField},
        traits::IsFFTField,
    },
    unsigned_integer::element::U256,
};
use std::fmt::Debug;

mod assets;
mod constants;
mod crypto;
mod utils;

/// Type alias for STARK field elements
pub type Fe = FieldElement<Stark252PrimeField>;

#[derive(Clone, Debug, Hash, Copy)]
pub struct MontgomeryConfigStark252CurvePrimeField;
impl IsModulus<U256> for MontgomeryConfigStark252CurvePrimeField {
    const MODULUS: U256 =
        U256::from_hex_unchecked("800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f");
}

pub type Stark252CurvePrimeField = U256PrimeField<MontgomeryConfigStark252CurvePrimeField>;

pub type FeScalar = FieldElement<Stark252CurvePrimeField>;

/// Type alias for STARK curve points
pub type CurvePoint = <StarkCurve as IsEllipticCurve>::PointRepresentation;
