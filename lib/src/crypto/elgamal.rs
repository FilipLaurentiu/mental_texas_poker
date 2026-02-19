use crate::{
    constants::CURVE_ORDER_FE, utils::{get_random_fe, inv_mod},
    CurvePoint,
    FE,
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
};
use std::ops::{Add, Mul, Neg};

struct ElGamalEncryption {
    c1: CurvePoint,
    c2: CurvePoint,
}

impl ElGamalEncryption {
    fn encrypt(pub_key: &CurvePoint, message: &FE) -> Self {
        let r = get_random_fe();
        let G = StarkCurve::generator();
        let M = G.operate_with_self(message.representative());
        let c1 = G.operate_with_self(r.representative());
        let c2 = M.operate_with(&pub_key.operate_with_self(r.representative()));

        Self { c1, c2 }
    }

    pub fn decrypt(self, private_key: &FE) -> CurvePoint {
        self.c2.operate_with(
            &self
                .c1
                .operate_with_self(private_key.representative())
                .neg(),
        )
    }
}

struct ElGamalVecEncryption {
    c1: CurvePoint,
    c2: Vec<CurvePoint>,
}

impl ElGamalVecEncryption {
    fn encrypt_vec(pub_key: &CurvePoint, elements: &[CurvePoint]) -> Self {
        let r = get_random_fe();
        let G = StarkCurve::generator();
        let c1 = G.operate_with_self(r.representative());

        let mut c2 = vec![];

        for card in elements {
            c2.push(card.operate_with(&pub_key.operate_with_self(r.representative())));
        }

        Self { c1, c2 }
    }

    fn decrypt_vec(&self, private_key: &FE) -> Vec<CurvePoint> {
        let priv_key_neg = inv_mod(private_key, &CURVE_ORDER_FE).unwrap();
        let R = self.c1.operate_with_self(priv_key_neg.representative());

        let mut decrypted_elements = vec![];

        for element in self.c2.iter() {
            decrypted_elements.push(element.operate_with(&R.neg()));
        }

        decrypted_elements
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::elgamal::ElGamalEncryption,
        utils::{cairo_short_string_to_fe, get_random_fe_scalar},
    };
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve,
        },
    };

    #[test]
    fn test_encryption_decryption() {
        let g = StarkCurve::generator();
        let message = cairo_short_string_to_fe("message").unwrap();
        let private_key = get_random_fe_scalar();
        let pub_key = g.operate_with_self(private_key.representative());

        let encrypted_message = ElGamalEncryption::encrypt(&pub_key, &message);
        let decrypted_message = encrypted_message.decrypt(&private_key);

        assert_eq!(
            decrypted_message,
            g.operate_with_self(message.representative())
        );
    }
}
