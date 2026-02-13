use crate::utils::get_random_felt;
use starknet_curve::curve_params::EC_ORDER;
use starknet_types_core::{
    curve::AffinePoint,
    felt::{Felt, NonZeroFelt},
};
use std::ops::{Add, Mul, Neg};

struct ElGamalEncryption {
    c1: AffinePoint,
    c2: AffinePoint,
}

impl ElGamalEncryption {
    fn encrypt(pub_key: &AffinePoint, message: &Felt) -> Self {
        let r = get_random_felt();
        let G = AffinePoint::generator();
        let M = G.mul(*message);
        let c1 = G.mul(r);
        let c2 = M + pub_key.mul(r);

        Self { c1, c2 }
    }

    pub fn decrypt(self, private_key: &Felt) -> AffinePoint {
        self.c2.add(self.c1.mul(*private_key).neg())
    }
}

struct ElGamalVecEncryption {
    c1: AffinePoint,
    c2: Vec<AffinePoint>,
}

impl ElGamalVecEncryption {
    fn encrypt_vec(pub_key: &AffinePoint, elements: &[AffinePoint]) -> Self {
        let r = get_random_felt();
        let G = AffinePoint::generator();
        let c1 = &G * r;

        let mut c2 = vec![];

        for card in elements {
            c2.push(card.clone() + pub_key * r);
        }

        Self { c1, c2 }
    }

    fn decrypt_vec(&self, private_key: &Felt) -> Vec<AffinePoint> {
        let priv_key_neg = private_key
            .mod_inverse(&NonZeroFelt::from_felt_unchecked(EC_ORDER))
            .unwrap();
        let R = &self.c1 * priv_key_neg;

        let mut decrypted_elements = vec![];

        for element in self.c2.iter() {
            decrypted_elements.push(element.clone() + R.neg());
        }

        decrypted_elements
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::elgamal::ElGamalEncryption,
        utils::get_random_stark_scalar,
    };
    use starknet::core::utils::cairo_short_string_to_felt;
    use starknet_types_core::curve::AffinePoint;
    use std::ops::Mul;

    #[test]
    fn test_encryption_decryption() {
        let message = cairo_short_string_to_felt("message").unwrap();
        let private_key = get_random_stark_scalar();
        let pub_key = AffinePoint::generator().mul(private_key);

        let encrypted_message = ElGamalEncryption::encrypt(&pub_key, &message);
        let decrypted_message = encrypted_message.decrypt(&private_key);

        assert_eq!(decrypted_message, AffinePoint::generator().mul(message));
    }
}
