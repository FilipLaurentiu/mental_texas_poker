#![allow(warnings)]

use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;
use lambdaworks_math::{
    elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve,
    field::{
        element::FieldElement, fields::fft_friendly::stark_252_prime_field::Stark252PrimeField,
    },
};

mod assets;
mod constants;
mod crypto;
mod utils;

/// Type alias for STARK field elements
pub type FE = FieldElement<Stark252PrimeField>;


/// Type alias for STARK curve points
pub type CurvePoint = <StarkCurve as IsEllipticCurve>::PointRepresentation;


