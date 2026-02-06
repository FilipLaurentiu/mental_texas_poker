use crate::utils::get_random_felt;
use starknet_types_core::{curve::AffinePoint, felt::Felt};
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
    fn encrypt_vec(pub_key: &AffinePoint, elements: &[Felt]) -> Self {
        unimplemented!()
    }

    fn decrypt_vec(&self, private_key: &Felt) -> Vec<AffinePoint> {

        unimplemented!()
    }
}
