use crate::{utils::get_random_fe, CurvePoint, Fe, FeScalar};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
};
use std::ops::{Add, Mul, Neg};

#[derive(Clone)]
pub struct ElGamalCiphertext {
    pub c1: CurvePoint,
    pub c2: CurvePoint,
}

impl ElGamalCiphertext {
    pub fn new(c1: CurvePoint, c2: CurvePoint) -> Self {
        Self { c1, c2 }
    }

    pub fn encrypt(pk: &CurvePoint, message: &FeScalar) -> Self {
        let r = get_random_fe();
        let G = StarkCurve::generator();
        let M = G.operate_with_self(message.representative());
        let c1 = G.operate_with_self(r.representative());
        let c2 = M.operate_with(&pk.operate_with_self(r.representative()));

        // c1 = r*G
        // c2 = M + r*PK
        Self { c1, c2 }
    }

    pub fn decrypt(&self, sk: &FeScalar) -> CurvePoint {
        // c2 - c1*sk
        self.c2
            .operate_with(&self.c1.operate_with_self(sk.representative()).neg())
    }

    fn add_encryption_layer(&self, pk: &CurvePoint) -> Self {
        let r = get_random_fe();
        let g = StarkCurve::generator();

        let r_g = g.operate_with_self(r.representative());
        let c2 = self
            .c2
            .operate_with(&pk.operate_with_self(r.representative()));

        Self { c1: r_g, c2 }
    }

    fn remove_encryption_layer(&self, sk: &Fe) -> CurvePoint {
        self.c2
            .operate_with(&self.c1.operate_with_self(sk.representative()).neg())
    }
}

struct ElGamalVecEncryption {
    c1: CurvePoint,
    c2: Vec<CurvePoint>,
}

impl ElGamalVecEncryption {
    fn encrypt_vec(pk: &CurvePoint, elements: &[CurvePoint]) -> Self {
        let r = get_random_fe();
        let G = StarkCurve::generator();
        let c1 = G.operate_with_self(r.representative());

        let mut c2 = vec![];

        for card in elements {
            c2.push(card.operate_with(&pk.operate_with_self(r.representative())));
        }

        Self { c1, c2 }
    }

    fn decrypt_vec(&self, sk: &Fe) -> Vec<CurvePoint> {
        let R = self.c1.operate_with_self(sk.representative());
        let mut decrypted_elements = vec![];
        for element in self.c2.iter() {
            decrypted_elements.push(element.operate_with(&R.neg()));
        }

        decrypted_elements
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::elgamal::ElGamalVecEncryption;
    use crate::{crypto::elgamal::ElGamalCiphertext, utils::{cairo_short_string_to_fe, get_random_fe_scalar}, Fe};
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
        let sk = get_random_fe_scalar();
        let pk = g.operate_with_self(sk.representative());

        let encrypted_message = ElGamalCiphertext::encrypt(&pk, &message);
        let decrypted_message = encrypted_message.decrypt(&sk);

        assert_eq!(
            decrypted_message,
            g.operate_with_self(message.representative())
        );
    }

    #[test]
    fn test_encryption_vector() {
        let g = StarkCurve::generator();
        let sk = get_random_fe_scalar();
        let pk = g.operate_with_self(sk.representative());
        let data = vec![
            g.operate_with_self(Fe::from(20).representative()),
            g.operate_with_self(Fe::from(21).representative()),
            g.operate_with_self(Fe::from(22).representative()),
        ];

        let encrypted_vec = ElGamalVecEncryption::encrypt_vec(&pk, &data);
        let decrypted_vec = encrypted_vec.decrypt_vec(&sk);

        assert_eq!(decrypted_vec, data);
    }

    #[test]
    fn encrypt_decrypt_with_individual_keys() {
        let g = StarkCurve::generator();
        let message = cairo_short_string_to_fe("message").unwrap();
        let M = g.operate_with_self(message.representative());

        let sk_1 = get_random_fe_scalar();
        let sk_2 = get_random_fe_scalar();
        let sk_3 = get_random_fe_scalar();

        let user1_enc =
            ElGamalCiphertext::encrypt(&g.operate_with_self(sk_1.representative()), &message);
        let user2_enc = user1_enc.add_encryption_layer(&g.operate_with_self(sk_2.representative()));
        let user3_enc = user2_enc.add_encryption_layer(&g.operate_with_self(sk_3.representative()));

        // remove user 3 encryption layer
        let user3_dec_c2 = user3_enc.remove_encryption_layer(&sk_3);
        assert_eq!(user3_dec_c2, user2_enc.c2);

        // remove user 3 encryption layer
        let user2_dec_c2 = user2_enc.remove_encryption_layer(&sk_2);
        assert_eq!(user2_dec_c2, user1_enc.c2);

        // decrypt final layer
        let user1_dec = ElGamalCiphertext::new(user1_enc.c1, user2_dec_c2).decrypt(&sk_1);
        assert_eq!(user1_dec, M);

        // remove user 1 encryption layer
        let user1_dec_c2 = user3_enc.remove_encryption_layer(&sk_1);
        // remove user 2 encryption layer
        let user2_dec_c2 =
            ElGamalCiphertext::new(user2_enc.c1, user1_dec_c2).remove_encryption_layer(&sk_2);

        let user3_r_enc = ElGamalCiphertext::new(user3_enc.c1, user2_dec_c2).decrypt(&sk_3);
        assert_eq!(user3_r_enc.to_affine(), M.to_affine());
    }
}
