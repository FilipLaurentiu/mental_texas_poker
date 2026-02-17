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
    table_id: FE,
    table_seat: usize,
    wallet_address: FE,
    secret_key_share: FE,
    encrypted_cards: Option<[CurvePoint; 2]>,
}

impl Player {
    fn new(table_id: FE, table_seat: usize, wallet_address: FE, secret_key_share: FE) -> Self {
        Self {
            table_id,
            table_seat,
            wallet_address,
            secret_key_share,
            encrypted_cards: None,
        }
    }

    /// Get the public key of the player.
    pub fn pub_key(&self) -> CurvePoint {
        StarkCurve::generator().operate_with_self(self.secret_key_share.representative())
    }

    /// Compute Diffie-Hellman secret key from the secret key and the other player public key.
    pub fn ecdh_secret(&self, player_pub_key: &CurvePoint) -> FE {
        let secret = player_pub_key.operate_with_self(self.secret_key_share.representative());
        *secret.to_affine().x()
    }

    /// Run Pedersen DKG.
    /// Returns encrypted coefficients for each player.
    pub fn run_pedersen_dkg(&self, players_pub_keys: &[CurvePoint]) -> Vec<EncryptedDKGShare> {
        let pedersen_dkg = PedersenDKG::new(players_pub_keys.len());

        let mut encrypted_coeffs = vec![];
        for (i, player_pub_key) in players_pub_keys.iter().enumerate() {
            let evaluations = pedersen_dkg
                .partial_shares
                .get(i + 1)
                .unwrap()
                .to_bytes_be();

            let ecdh_secret = self.ecdh_secret(player_pub_key).to_bytes_be();
            let ciphertext =
                EncryptedDKGShare::encrypt_dkg_share(&ecdh_secret, evaluations.as_ref());
            encrypted_coeffs.push(ciphertext);
        }
        encrypted_coeffs
    }

    /// Receive DKG share from player.
    /// - `pedersen_dkg_proof` - Pedersen DKG proof
    /// - `encrypted_dkg_share` - Encrypted DKG share
    /// - `pub_key` - Sender public key
    pub fn receive_dkg_share(
        self,
        pedersen_dkg_proof: &PedersenDKGProof,
        encrypted_dkg_share: EncryptedDKGShare,
        pub_key: &CurvePoint,
    ) {
        let ecdh_secret = self.ecdh_secret(pub_key).to_bytes_be();
        let dkg_share = encrypted_dkg_share.decrypt_dkg_share(ecdh_secret).unwrap();
        pedersen_dkg_proof.verify(dkg_share);
        
        
    }
}

struct EncryptedDKGShare {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

impl EncryptedDKGShare {
    fn new(ciphertext: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self { ciphertext, nonce }
    }

    /// Encrypt polynomial coefficient with the player public key.
    /// Returns (ciphertext, nonce)
    fn encrypt_dkg_share(ecdh_secret: &[u8; 32], coefficient: &[u8]) -> EncryptedDKGShare {
        let cipher = XChaCha20Poly1305::new(<&Key<XChaCha20Poly1305>>::from(ecdh_secret));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, coefficient.as_ref()).unwrap();

        EncryptedDKGShare::new(ciphertext, nonce.to_vec())
    }

    /// Decrypt DKG share from player
    fn decrypt_dkg_share(&self, secret_key: [u8; 32]) -> Result<FE, Error> {
        let cipher = XChaCha20Poly1305::new(<&Key<XChaCha20Poly1305>>::from(&secret_key));
        let plaintext_bytes = cipher.decrypt(
            XNonce::from_slice(self.nonce.as_ref()),
            self.ciphertext.as_ref(),
        )?;

        Ok(FE::from_bytes_be(&plaintext_bytes).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::get_random_fe;
    use crate::{assets::player::Player, FE};

    #[test]
    fn test_dkg() {
        let table_id = get_random_fe();
        let player1 = Player::new(table_id, 1, FE::from(1), FE::from(11));
        let player2 = Player::new(table_id, 2, FE::from(2), FE::from(22));
        let player3 = Player::new(table_id, 3, FE::from(3), FE::from(33));

        let players_pub = vec![player1.pub_key(), player2.pub_key(), player3.pub_key()];
        let pedersen_dkg_player1 = player1.run_pedersen_dkg(&players_pub);
        let pedersen_dkg_player2 = player1.run_pedersen_dkg(&players_pub);
        let pedersen_dkg_player3 = player1.run_pedersen_dkg(&players_pub);
    }
}
