use crate::{
    assets::card::Card, crypto::{
        ecdh::ecdh_secret,
        pedersen_dkg::{EncryptedDKGShare, PedersenDKG, PedersenDKGProof},
    },
    CurvePoint,
    FE,
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    traits::ByteConversion,
};
use std::collections::HashMap;

/// - `wallet` - on-chain wallet address
/// - `secret_key_share` - share of the distributed key
/// - `encrypted_cards` - encrypted cards that player owns
pub struct Player {
    table_id: FE,
    table_seat: usize,
    wallet_address: FE,
    secret_key_share: FE,
    encrypted_cards: Option<[CurvePoint; 2]>,
    decrypted_cards: Option<[Card; 2]>,
    pedersen_dkg: Option<PedersenDKG>,
    dkg_shares: Vec<FE>,
    received_dkg_shares: HashMap<(FE, FE), bool>,
}

#[derive(Debug)]
enum ReceiveDKGShareError {
    AlreadyReceived,
    DKGDecryptionFail,
    InvalidDKGProof,
    InvalidShareElement,
}

#[derive(Debug)]
enum GetPlayerDKGShareError {
    InvalidPedersenDKG,
    InvalidTableSeat,
}

impl Player {
    fn new(table_id: FE, table_seat: usize, wallet_address: FE, secret_key_share: FE) -> Self {
        Self {
            table_id,
            table_seat,
            wallet_address,
            secret_key_share,
            encrypted_cards: None,
            decrypted_cards: None,
            pedersen_dkg: None,
            dkg_shares: vec![],
            received_dkg_shares: HashMap::new(),
        }
    }

    /// Get the public key of the player.
    pub fn pub_key(&self) -> CurvePoint {
        StarkCurve::generator().operate_with_self(self.secret_key_share.representative())
    }

    /// Run Pedersen DKG.
    pub fn run_pedersen_dkg(&mut self, players_pub_keys: &[CurvePoint]) {
        let pedersen_dkg = PedersenDKG::new(
            players_pub_keys.len(),
            &self.secret_key_share,
            players_pub_keys,
        );

        self.pedersen_dkg = Some(pedersen_dkg);
    }

    pub fn get_player_dkg_share(
        &self,
        table_seat: usize,
    ) -> Result<&EncryptedDKGShare, GetPlayerDKGShareError> {
        if table_seat == self.table_seat {
            Err(GetPlayerDKGShareError::InvalidTableSeat)
        } else {
            Ok(self
                .pedersen_dkg
                .as_ref()
                .ok_or_else(|| GetPlayerDKGShareError::InvalidPedersenDKG)?
                .encrypted_dkg_shares
                .get(table_seat)
                .ok_or_else(|| GetPlayerDKGShareError::InvalidTableSeat)?)
        }
    }

    pub fn get_pedersen_dkg_proof(&self) -> Option<&PedersenDKGProof> {
        self.pedersen_dkg.as_ref().map(|ped_dkg| &ped_dkg.proof)
    }

    /// Receive DKG share from player.
    /// - `pedersen_dkg_proof` - Pedersen DKG proof
    /// - `encrypted_dkg_share` - Encrypted DKG share
    /// - `pub_key` - Sender public key
    pub fn receive_dkg_share(
        &mut self,
        pedersen_dkg_proof: &PedersenDKGProof,
        encrypted_dkg_share: &EncryptedDKGShare,
        pub_key: &CurvePoint,
    ) -> Result<(), ReceiveDKGShareError> {
        if let Some(received) = self.received_dkg_shares.get(&(*pub_key.x(), *pub_key.y())) {
            if *received {
                return Err(ReceiveDKGShareError::AlreadyReceived);
            }
        }

        let ecdh_secret = ecdh_secret(&self.secret_key_share, pub_key).to_bytes_be();
        let dkg_share = encrypted_dkg_share
            .decrypt_dkg_share(&ecdh_secret)
            .map_err(|_| ReceiveDKGShareError::DKGDecryptionFail)?;

        let share_fe =
            FE::from_bytes_be(&dkg_share).map_err(|_| ReceiveDKGShareError::InvalidShareElement)?;

        if pedersen_dkg_proof.verify(share_fe, pub_key) {
            self.dkg_shares.push(share_fe);
            self.received_dkg_shares
                .insert((*pub_key.x(), *pub_key.y()), true);
            Ok(())
        } else {
            Err(ReceiveDKGShareError::InvalidDKGProof)
        }
    }

    pub fn dkg_share(&self) -> FE {
        // sum of dkg shares from other players
        let dkg_shares_sum: FE = self.dkg_shares.iter().fold(FE::zero(), |a, b| a + b);

        dkg_shares_sum + self.secret_key_share
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        assets::{
            player::Player,
            poker_table::{BuyInPokerTableType, PokerTable, PokerTableType, Rake},
        },
        FE,
    };
    use crypto_bigint::U256;

    #[test]
    fn test_dkg() {
        let mut poker_table = PokerTable::new(
            PokerTableType::BuyIn(BuyInPokerTableType {
                buy_in: U256::from_u8(10),
            }),
            6,
            2,
            Rake::default(),
        );
        let mut player1 = Player::new(poker_table.table_id, 1, FE::from(1), FE::from(11));
        let mut player2 = Player::new(poker_table.table_id, 2, FE::from(2), FE::from(22));
        let mut player3 = Player::new(poker_table.table_id, 3, FE::from(3), FE::from(33));

        poker_table
            .add_player(
                &player1.wallet_address,
                &player1.pub_key(),
                U256::from_u128(250),
            )
            .unwrap();
        poker_table
            .add_player(
                &player2.wallet_address,
                &player2.pub_key(),
                U256::from_u128(400),
            )
            .unwrap();
        poker_table
            .add_player(
                &player3.wallet_address,
                &player3.pub_key(),
                U256::from_u128(300),
            )
            .unwrap();

        let players_pub = vec![player1.pub_key(), player2.pub_key(), player3.pub_key()];
        player1.run_pedersen_dkg(&players_pub);
        player2.run_pedersen_dkg(&players_pub);
        player3.run_pedersen_dkg(&players_pub);

        player1
            .receive_dkg_share(
                &player2.get_pedersen_dkg_proof().unwrap(),
                player2.get_player_dkg_share(0).unwrap(),
                &player2.pub_key(),
            )
            .unwrap();

        player1
            .receive_dkg_share(
                &player3.get_pedersen_dkg_proof().unwrap(),
                player3.get_player_dkg_share(0).unwrap(),
                &player3.pub_key(),
            )
            .unwrap();
    }
}
