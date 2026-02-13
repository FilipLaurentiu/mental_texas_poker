use crate::{
    constants::CURVE_ORDER_FE, utils::{get_random_fe_scalar, mul_mod},
    CurvePoint,
    FE,
};

use crypto_bigint::rand_core::RngCore;

use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    traits::ByteConversion,
};

use rand::{Rng, SeedableRng};
use std::{
    hash::Hash,
    ops::{Div, Mul, Neg},
};

struct SchnorrProof {
    message: FE,
    signature: (CurvePoint, FE),
}

impl SchnorrProof {
    pub fn sign_message(private_key: &FE, message: &FE) -> Self {
        let g = StarkCurve::generator();
        // Choose a random k field element. This element should be different in each signature.
        let k = get_random_fe_scalar();
        // R = k*G.
        let R = g.operate_with_self(k.representative()).to_affine();

        // compute e = H(R, H(message))
        let e = PedersenStarkCurve::hash(&PedersenStarkCurve::hash(R.x(), R.y()), message);

        let e_p = g
            .operate_with_self(mul_mod(private_key, &e, &CURVE_ORDER_FE).representative())
            .to_affine();

        println!("ep  {:?}", e_p);
        // s = k + private_key * e
        let s = k + mul_mod(private_key, &e, &CURVE_ORDER_FE);

        Self {
            message: message.clone(),
            signature: (R, s),
        }
    }

    pub fn verify_signature(&self, public_key: &CurvePoint) -> bool {
        let g = StarkCurve::generator();
        let (R, s) = &self.signature;

        let e = PedersenStarkCurve::hash(&PedersenStarkCurve::hash(R.x(), R.y()), &self.message);

        let e_p = public_key.operate_with_self(e.representative()).to_affine();
        println!("ep  {:?}", e_p);

        let R_v = g
            .operate_with_self(s.representative())
            .operate_with(&public_key.operate_with_self(e.representative()).neg())
            .to_affine();

        R_v == *R
    }
}

#[cfg(test)]
mod tests {
    use crate::{crypto::schnorr_proof::SchnorrProof, utils::get_random_fe_scalar, FE};
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve,
        },
    };

    #[test]
    fn test_proof() {
        let secret_key = get_random_fe_scalar();

        let message = FE::from(10);
        let proof = SchnorrProof::sign_message(&secret_key, &message);

        let pub_key = StarkCurve::generator()
            .operate_with_self(secret_key.representative())
            .to_affine();

        let is_valid = proof.verify_signature(&pub_key);
        println!("Valid proof: {}", is_valid);
        assert!(is_valid == true);
    }
}
