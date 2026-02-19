use crate::FE;
use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
use lambdaworks_math::field::{
    element::FieldElement, fields::fft_friendly::stark_252_prime_field::Stark252PrimeField,
};

pub fn hash_array(felts: &[FE]) -> FE {
    let data_len = FE::from(felts.len() as u64);
    let current_hash: FieldElement<Stark252PrimeField> = felts
        .iter()
        .fold(FieldElement::zero(), |current_hash, felt| {
            PedersenStarkCurve::hash(&current_hash, &felt)
        });
    PedersenStarkCurve::hash(&current_hash, &data_len)
}
