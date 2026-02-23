use crate::{
    crypto::{ecdh::ecdh_secret, schnorr_proof::SchnorrProof}, utils::get_random_fe_scalar,
    CurvePoint,
    FE,
};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, Key, KeyInit, OsRng}, Error, XChaCha20Poly1305,
    XNonce,
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    polynomial::Polynomial,
    traits::ByteConversion,
};

/// Pedersen DKG Proof
///
/// - `secret_pok` - Proof of knowledge of the shared secret.
/// - `commitment` - Commitment of the coefficients. The first entry is the commitment of the secret value.
pub struct PedersenDKGProof {
    secret_pok: SchnorrProof,
    pub commitments: Vec<CurvePoint>,
}

impl PedersenDKGProof {
    fn new(commitments: Vec<CurvePoint>, secret_pok: SchnorrProof) -> Self {
        Self {
            secret_pok,
            commitments,
        }
    }

    pub fn size(&self) -> usize {
        self.commitments.len() - 1
    }

    /// Verify Pedersen DKG commitment.
    ///
    /// - `dkg_share` - Received dkg share
    /// - `pub_key` - Sender public key
    pub fn verify(&self, dkg_share: FE, pk: &FE) -> bool {
        let dkg_polynomial_degree = self.size();

        let mut x = dkg_share.clone();
        let acc = StarkCurve::generator();
        for i in 1..dkg_polynomial_degree {
            let coefficient_commitment = self.commitments.get(i).unwrap();
            acc.operate_with(&coefficient_commitment.operate_with_self(x.representative()));
            x = x.double();
        }
        let dkg_share_point = StarkCurve::generator().operate_with_self(dkg_share.representative());

        self.secret_pok.verify_signature(pk) && acc == dkg_share_point
    }
}

/// Pedersen Distributed Key Generation
pub struct PedersenDKG {
    coefficients: Vec<FE>,
    pub proof: PedersenDKGProof,
    pub partial_shares: Vec<FE>,
    pub encrypted_dkg_shares: Vec<EncryptedDKGShare>,
}

impl PedersenDKG {
    /// - `n` - polynomial degree
    pub fn new(n: usize, private_key: &FE, players_pub_keys: &[FE]) -> Self {
        let mut random_coefficients = vec![get_random_fe_scalar(); n + 1];

        let polynomial = Polynomial::new(&random_coefficients);

        let mut commitments = vec![];
        let mut partial_shares = vec![];
        let g = StarkCurve::generator();

        // commitment of the secret value, the constant part of the polynomial, f(0).
        let secret = random_coefficients.first().unwrap();
        commitments.push(g.clone().operate_with_self(secret.representative()));

        for i in 1..n + 1 {
            let field_el = FE::from(i as u64);
            let evaluation = polynomial.evaluate(&field_el);
            partial_shares.push(evaluation);
            let commitment = g
                .clone()
                .operate_with_self(random_coefficients.get(i).unwrap().representative());
            commitments.push(commitment);
        }

        let secret_pok = SchnorrProof::sign_message(private_key, secret);

        let mut encrypted_dkg_shares = vec![];
        for (i, pk) in players_pub_keys.iter().enumerate() {
            let evaluations = partial_shares.get(i).unwrap().to_bytes_be();

            let ecdh_secret = ecdh_secret(private_key, pk).unwrap().to_bytes_be();
            let ciphertext =
                EncryptedDKGShare::encrypt_dkg_share(&ecdh_secret, evaluations.as_ref());
            encrypted_dkg_shares.push(ciphertext);
        }

        Self {
            coefficients: random_coefficients,
            proof: PedersenDKGProof {
                secret_pok,
                commitments,
            },
            partial_shares,
            encrypted_dkg_shares,
        }
    }
}

#[derive(Clone)]
pub struct EncryptedDKGShare {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

impl EncryptedDKGShare {
    fn new(ciphertext: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self { ciphertext, nonce }
    }

    /// Encrypt DKG share with the player public key.
    /// Returns (ciphertext, nonce)
    fn encrypt_dkg_share(ecdh_secret: &[u8; 32], dkg_share: &[u8]) -> EncryptedDKGShare {
        let cipher = XChaCha20Poly1305::new(<&Key<XChaCha20Poly1305>>::from(ecdh_secret));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);

        let xnonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(&xnonce, dkg_share.as_ref()).unwrap();

        EncryptedDKGShare::new(ciphertext, xnonce.to_vec())
    }

    /// Decrypt DKG share from player
    pub fn decrypt_dkg_share(&self, ecdh_secret: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305::new(<&Key<XChaCha20Poly1305>>::from(ecdh_secret));
        let xnonce = XNonce::from_slice(&self.nonce);
        let dkg_share = cipher.decrypt(xnonce, self.ciphertext.as_ref())?;

        Ok(dkg_share)
    }
}

#[cfg(test)]
mod tests {
    use crate::{crypto::pedersen_dkg::EncryptedDKGShare, FE};
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve,
        },
        traits::ByteConversion,
    };

    #[test]
    fn test_encryption_dkg_share() {
        let share = FE::from(230).to_bytes_be();
        let key = FE::from(12345678);
        let ecdh_key = StarkCurve::generator()
            .operate_with_self(key.representative())
            .x()
            .to_bytes_be();

        let ciphertext = EncryptedDKGShare::encrypt_dkg_share(&ecdh_key, &share);

        assert_eq!(ciphertext.decrypt_dkg_share(&ecdh_key).unwrap(), share);
    }
}
