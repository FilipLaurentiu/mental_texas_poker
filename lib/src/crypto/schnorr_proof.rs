use crate::{
    constants::CURVE_ORDER_FE,
    utils::{add_mod, get_random_fe_scalar, mul_mod},
    Fe,
};
use crypto_bigint::rand_core::RngCore;
use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    traits::ByteConversion,
};

use crate::crypto::utils::new_ec_from_x;
use rand::{Rng, SeedableRng};
use std::{
    hash::Hash,
    ops::{Div, Mul, Neg},
};

/// Schnorr signature
///
/// - `message` - Signed message
/// - `signature` - Compressed signature (Rx - compressed, s)
pub struct SchnorrProof {
    message: Fe,
    signature: (Fe, Fe),
}

impl SchnorrProof {
    pub fn sign_message(private_key: &Fe, message: &Fe) -> Self {
        let g = StarkCurve::generator();
        // Choose a random k field element. This element should be different in each signature.
        let k = get_random_fe_scalar();
        // R = k*G.
        let R = g.operate_with_self(k.representative()).to_affine();

        // for consistency
        let R = new_ec_from_x(R.x()).unwrap();

        // compute e = H(R, H(message))
        let e = PedersenStarkCurve::hash(&PedersenStarkCurve::hash(R.x(), R.y()), message);

        // s = k + private_key * e
        let s = add_mod(
            &k,
            &mul_mod(private_key, &e, &CURVE_ORDER_FE),
            &CURVE_ORDER_FE,
        );

        Self {
            message: message.clone(),
            signature: (*R.x(), s),
        }
    }

    pub fn verify_signature(&self, pk: &Fe) -> bool {
        let g = StarkCurve::generator();
        let (r, s) = &self.signature;

        let R = new_ec_from_x(r).unwrap();

        let e = PedersenStarkCurve::hash(&PedersenStarkCurve::hash(R.x(), R.y()), &self.message);

        if let Some(pub_key) = new_ec_from_x(pk) {
            let R_v = g
                .operate_with_self(s.representative())
                .operate_with(&pub_key.operate_with_self(e.representative()).neg())
                .to_affine();

            R_v == R
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{crypto::schnorr_proof::SchnorrProof, utils::get_random_fe_scalar, Fe};
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve,
        },
    };

    #[test]
    fn test_proof() {
        let secret_key = get_random_fe_scalar();

        let message = Fe::from(10);
        let proof = SchnorrProof::sign_message(&secret_key, &message);

        let pub_key = StarkCurve::generator()
            .operate_with_self(secret_key.representative())
            .to_affine();

        let is_valid = proof.verify_signature(&pub_key.x());
        println!("Valid proof: {}", is_valid);
        assert_eq!(is_valid, true);
    }
}
