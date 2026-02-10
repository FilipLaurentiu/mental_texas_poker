use crate::utils::mul_mod_floor;
use crypto_bigint::{
    NonZero, U256,
    rand_core::{OsRng, RngCore},
};
use rand::{
    Rng,
    SeedableRng
};
use starknet::core::crypto::compute_hash_on_elements;
use starknet_curve::curve_params::EC_ORDER;
use starknet_types_core::{
    curve::AffinePoint,
    felt::Felt,
    hash::{Pedersen, StarkHash},
};
use std::ops::{Mul, Neg};

struct SchnorrProof {
    R: AffinePoint,
    b: Felt,
    pub_key: AffinePoint,
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
    const PRIME: NonZero<U256> = NonZero::<U256>::new_unwrap(U256::from_be_hex(
        "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
    ));
    let mut rng = OsRng::default();
    let mut buffer = [0u8; 32];
    rng.fill_bytes(&mut buffer);
    let random_u256 = U256::from_be_slice(&buffer);
    let secret_scalar = random_u256.rem(&PRIME);

    // It's safe to unwrap here as we're 100% sure it's not out of range
    let secret_scalar = Felt::from_bytes_be_slice(&secret_scalar.to_be_bytes());

    secret_scalar
}

impl SchnorrProof {
    fn generate_proof(secret_key: &Felt, challenge: Felt) -> Self {
        let r = get_random_stark_scalar();
        let R = AffinePoint::generator().mul(r);
        let pub_key = AffinePoint::generator().mul(*secret_key);

        let c = compute_hash_on_elements(&[challenge, R.x(), R.y(), pub_key.x(), pub_key.y()]);

        let b = r + mul_mod_floor(&c, &secret_key, &EC_ORDER);

        Self { R, b, pub_key }
    }

    fn verify_proof(&self, challenge: Felt) -> bool {
        let c = Pedersen::hash_array(&[
            challenge,
            self.R.x(),
            self.R.y(),
            self.pub_key.x(),
            self.pub_key.y(),
        ]);

        AffinePoint::generator().mul(self.b) == self.R.clone() + self.pub_key.mul(c)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::schnorr_proof::{SchnorrProof, get_random_stark_scalar};
    use starknet::core::crypto::{ecdsa_sign, ecdsa_verify};
    use starknet_crypto::{get_public_key, pedersen_hash, verify};
    use starknet_types_core::{curve::AffinePoint, felt::Felt, hash::StarkHash};
    use std::ops::Mul;

    #[test]
    fn test_proof() {
        let secret_key = get_random_stark_scalar();
        // let secret_key = Felt::from_dec_str("123456").unwrap();

        let challenge = Felt::TWO;
        let proof = SchnorrProof::generate_proof(&secret_key, challenge);

        let is_valid = proof.verify_proof(challenge);
        println!("Valid proof: {}", is_valid);
        assert!(is_valid == true);
    }

    #[test]
    fn test_ecdsa() {
        let priv_key = get_random_stark_scalar();
        let msg = pedersen_hash(&Felt::TWO, &Felt::THREE);
        let signature = ecdsa_sign(&priv_key, &msg).unwrap();

        assert!(ecdsa_verify(&get_public_key(&priv_key), &msg, &signature.into()).unwrap());
    }

    #[test]
    fn test_proof_with_fixed_values() {
        // Use fixed values for reproducibility
        let secret_key = Felt::from(12345u64);
        let challenge = Felt::ONE;

        let proof = SchnorrProof::generate_proof(&secret_key, challenge);

        println!("R: {:?}", proof.R);
        println!("b: {}", proof.b);
        println!("pub_key: {:?}", proof.pub_key);

        let is_correct = proof.verify_proof(challenge);

        // Manually verify
        let G = AffinePoint::generator();
        let c = starknet_types_core::hash::Pedersen::hash_array(&[
            challenge,
            proof.R.x(),
            proof.R.y(),
            proof.pub_key.x(),
            proof.pub_key.y(),
        ]);

        println!("Challenge hash c: {}", c);

        let lhs = G.mul(proof.b);
        let rhs = proof.R + proof.pub_key.mul(c);

        println!("LHS (g^b): {:?}", lhs);
        println!("RHS (R + c*P): {:?}", rhs);
        println!("Are they equal? {}", lhs == rhs);

        assert!(is_correct, "Proof verification should pass");
    }
}
