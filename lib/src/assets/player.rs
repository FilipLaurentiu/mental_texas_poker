use crate::{
    crypto::pedersen_dkg::{PedersenDKG, PedersenDKGProof}, CurvePoint,
    FE,
};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, Key, KeyInit, OsRng}, Error, XChaCha20Poly1305,
    XNonce,
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    traits::ByteConversion,
};

/// - `wallet` - on-chain wallet address
/// - `secret_key_share` - share of the distributed key
/// - `encrypted_cards` - encrypted cards that player owns
pub struct Player {
    wallet: FE,
    secret_key_share: FE,
    encrypted_cards: [CurvePoint; 2],
}

impl Player {
    /// Get the public key of the player.
    pub fn pub_key(&self) -> CurvePoint {
        StarkCurve::generator().operate_with_self(self.secret_key_share.representative())
    }

    /// Compute Diffie-Hellman secret key from the secret key and the other player public key.
    pub fn ecdh_secret(&self, player_pub_key: &CurvePoint) -> FE {
        let secret = player_pub_key.operate_with_self(self.secret_key_share.representative());
        *secret.to_affine().x()
    }

    pub fn pedersen_dkg(&self, players_pub_keys: &[CurvePoint]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let pedersen_dkg = PedersenDKG::new(players_pub_keys.len());

        let mut res = vec![];
        for (i, player_pub_key) in players_pub_keys.iter().enumerate() {
            let coefficient = pedersen_dkg.coefficients.get(i + 1).unwrap().to_bytes_be();
            let ciphertext = self.encrypt_dkg_share(player_pub_key, coefficient.as_ref());
            res.push(ciphertext);
        }
        res
    }

    /// Encrypt polynomial coefficient with the player public key
    fn encrypt_dkg_share(&self, pub_key: &CurvePoint, coefficient: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let ecdh_secret = self.ecdh_secret(pub_key).to_bytes_be();
        let cipher = XChaCha20Poly1305::new(<&Key<XChaCha20Poly1305>>::from(&ecdh_secret));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, coefficient.as_ref()).unwrap();

        (ciphertext, nonce.to_vec())
    }

    /// Decrypt DKG share from player
    fn decrypt_dkg_share(
        &self,
        pub_key: &CurvePoint,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<FE, Error> {
        let ecdh_secret = self.ecdh_secret(pub_key).to_bytes_be();
        let cipher = XChaCha20Poly1305::new(<&Key<XChaCha20Poly1305>>::from(&ecdh_secret));

        let plaintext_bytes = cipher.decrypt(XNonce::from_slice(nonce), ciphertext.as_ref())?;

        Ok(FE::from_bytes_be(&plaintext_bytes).unwrap())
    }

    /// Decrypt and verify Pedersen DKG commitment.
    fn verify_dkg(
        &self,
        pub_key: &CurvePoint,
        ciphertext: &[u8],
        nonce: &[u8],
        pedersen_dkg_proof: &PedersenDKGProof,
    ) -> bool {
        let dkg_share = self.decrypt_dkg_share(pub_key, ciphertext, nonce).unwrap();
        let dkg_polynomial_degree = pedersen_dkg_proof.size();

        let mut x = dkg_share.clone();
        let acc = StarkCurve::generator();
        for i in 1..dkg_polynomial_degree {
            let coefficient_commitment = pedersen_dkg_proof.commitments.get(i).unwrap();
            acc.operate_with(&coefficient_commitment.operate_with_self(x.representative()));
            x = x.double();
        }
        let dkg_share_point = StarkCurve::generator().operate_with_self(dkg_share.representative());

        acc == dkg_share_point
    }
}
