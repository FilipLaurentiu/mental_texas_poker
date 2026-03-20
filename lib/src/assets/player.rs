use crate::assets::card::EncryptedCard;
use crate::assets::deck::CardTable;
use crate::utils::get_random_fe_scalar;
use crate::{
    assets::{
        card::Card,
        poker_table::{PokerTable, PokerTableStatus, PokerTableStatusPlaying},
    }, crypto::{
        ecdh::ecdh_key,
        ecdsa::EcdsaSignature,
        pedersen_dkg::{EncryptedDKGShare, NewPedersenDKGError, PedersenDKG, PedersenDKGProof},
        utils::new_ec_from_x,
    },
    CurvePoint,
    Fe,
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    traits::ByteConversion,
};
use std::{cmp::PartialEq, collections::HashMap};

#[derive(PartialEq, Clone, Eq, Hash)]
pub struct Account {
    pub address: Fe,
    pub pk: Fe,
    sk: Fe,
}

impl Account {
    pub fn new(address: Fe, sk: Fe) -> Self {
        let pub_key = StarkCurve::generator()
            .operate_with_self(sk.representative())
            .to_affine();
        Self {
            address,
            pk: *pub_key.x(),
            sk,
        }
    }

    pub fn is_valid_signature(&self, hash: Fe, signature: &[Fe]) -> bool {
        if signature.len() != 2 {
            return false;
        }
        if let Some(pk) = new_ec_from_x(&self.pk) {
            let signature =
                EcdsaSignature::new(&signature.get(0).unwrap(), signature.get(1).unwrap()).unwrap();

            signature.verify(&hash.to_bytes_be(), &pk).is_ok()
        } else {
            false
        }
    }
}

/// - `account` - on-chain account\
/// - `encrypted_cards` - encrypted cards that player owns
/// - `decrypted_cards` - decrypted cards
/// - `pedersen_dkg` - Pedersen DKG share
/// - `secret_dkg_share` - share of the distributed key
pub struct Player<'a> {
    account: &'a Account,
    encrypted_cards: Option<[EncryptedCard; 2]>,
    decrypted_cards: Option<[Card; 2]>,
    game_sk: Fe,
    pedersen_dkg: Option<PedersenDKG>,
    secret_dkg_share: Fe,
    dkg_shares: Vec<Fe>,
    // address -> share
    received_dkg_shares: HashMap<Fe, Fe>,
}

#[derive(Debug)]
enum ReceiveDKGShareError {
    AlreadyReceived,
    DKGDecryptionFail,
    ECDHSecretFail,
    InvalidDKGProof,
    InvalidSharedElement,
}

#[derive(Debug)]
enum GetPlayerDKGShareError {
    MissingPedersenDKG,
    UnfinishedPedersenDKG,
    InvalidPedersenDKG,
    InvalidTableSeat,
    ECDHSecretFail,
}

#[derive(Debug)]
pub enum RunPedersenDKGError {
    InvalidTableStatus,
    InvalidTable,
    InvalidDKG,
    PedersenDKGError(NewPedersenDKGError),
}

pub struct DKGCommitment {
    pub commitment_hash: Fe,
    pub signature: EcdsaSignature,
}

impl<'a> Player<'a> {
    fn new(account: &'a Account) -> Self {
        let session_key = get_random_fe_scalar();
        Self {
            account,
            encrypted_cards: None,
            decrypted_cards: None,
            game_sk: session_key,
            pedersen_dkg: None,
            secret_dkg_share: Fe::zero(),
            dkg_shares: vec![],
            received_dkg_shares: HashMap::new(),
        }
    }

    /// Get the public key of the player.
    pub fn pub_key(&self) -> &Fe {
        &self.account.pk
    }

    // Current game pub key.
    pub fn game_pk(&self) -> CurvePoint {
        StarkCurve::generator().operate_with_self(self.game_sk.representative())
    }

    /// Add encryption for the card.
    ///
    /// Initial state (c1, c2) = (0, k·G), where k -> card identifier
    /// Encryption: (c1 + r·G,  c2 + r·P), where P is the `game_key`
    pub fn encrypt_card(
        &self,
        table: &PokerTable,
        encrypted_card: &EncryptedCard,
    ) -> EncryptedCard {
        let game_pk = &table.game_pk().unwrap();
        let r = get_random_fe_scalar();

        let c1 = encrypted_card
            .c1
            .operate_with(&StarkCurve::generator().operate_with_self(r.representative()));

        let c2 = encrypted_card
            .c2
            .operate_with(&game_pk.operate_with_self(r.representative()));

        EncryptedCard { c1, c2 }
    }

    /// Player receive [D_0,D_1,..,D_n] from player the other players in order to decrypt his cards.
    /// He needs to add his share into the list.
    ///
    /// $D_{i} = sk_{i} · C1$
    ///
    /// Decryption: C2 - (D₁ + D₂ + ... + Dₙ).
    pub fn decrypt_cards(&mut self, players_shares: &[(CurvePoint, CurvePoint)]) {
        let encrypted_cards = self.encrypted_cards.as_ref().expect("No cards in hand");

        let d_0 = encrypted_cards[0]
            .c1
            .operate_with_self(self.game_sk.representative());
        let d_1 = encrypted_cards[1]
            .c1
            .operate_with_self(self.game_sk.representative());

        let shares_sum_0 = players_shares
            .iter()
            .fold(CurvePoint::neutral_element(), |acc, d| {
                acc.operate_with(&d.0)
            })
            .operate_with(&d_0);

        let shares_sum_1 = players_shares
            .iter()
            .fold(CurvePoint::neutral_element(), |acc, d| {
                acc.operate_with(&d.1)
            })
            .operate_with(&d_1);

        let enc_card_1 = encrypted_cards[0].c2.operate_with(&shares_sum_0.neg());
        let enc_card_2 = encrypted_cards[1].c2.operate_with(&shares_sum_1.neg());

        let card_table = CardTable::new();
        let card_1 = card_table
            .get_card_number(enc_card_1)
            .expect("Invalid card");
        let card_2 = card_table
            .get_card_number(enc_card_2)
            .expect("Invalid card");

        self.decrypted_cards = Some([
            Card::from_index(*card_1).unwrap(),
            Card::from_index(*card_2).unwrap(),
        ]);
    }

    /// Run Pedersen DKG.
    pub fn run_pedersen_dkg(&mut self, table: &PokerTable) -> Result<Fe, RunPedersenDKGError> {
        let pedersen_dkg = PedersenDKG::new(&self.account.sk, &table.players_accounts)
            .map_err(|err| RunPedersenDKGError::PedersenDKGError(err))?;

        let commitment_hash = pedersen_dkg.proof.commitment_hash();

        // add users share to the
        self.secret_dkg_share = *pedersen_dkg
            .dkg_shares
            .get(&self.account.address)
            .ok_or(RunPedersenDKGError::InvalidDKG)?;

        self.pedersen_dkg = Some(pedersen_dkg);

        Ok(commitment_hash)
    }

    /// Get encrypted partial DKG share for the specific user
    pub fn get_player_dkg_share(
        &self,
        table: &PokerTable,
        account: &Account,
    ) -> Result<EncryptedDKGShare, GetPlayerDKGShareError> {
        if table.status
            != PokerTableStatus::Playing(PokerTableStatusPlaying::PedersenDKGCommitmentsRegistered)
        {
            return Err(GetPlayerDKGShareError::UnfinishedPedersenDKG);
        }

        if self.account.address == account.address {
            return Err(GetPlayerDKGShareError::InvalidTableSeat);
        }

        let dkg_share = self
            .pedersen_dkg
            .as_ref()
            .ok_or_else(|| GetPlayerDKGShareError::MissingPedersenDKG)?
            .dkg_shares
            .get(&account.address)
            .ok_or_else(|| GetPlayerDKGShareError::InvalidPedersenDKG)?;

        let ecdh_key = ecdh_key(&self.account.sk, &account.pk)
            .map_err(|_| GetPlayerDKGShareError::ECDHSecretFail)?;

        let ciphertext =
            EncryptedDKGShare::encrypt_dkg_share(&ecdh_key.to_bytes_be(), &dkg_share.to_bytes_be());

        // TODO: Sign the result
        Ok(ciphertext)
    }

    pub fn get_pedersen_dkg_proof(&self) -> Option<&PedersenDKGProof> {
        self.pedersen_dkg.as_ref().map(|ped_dkg| &ped_dkg.proof)
    }

    /// Receive DKG share from player.
    /// - `pedersen_dkg_proof` - Pedersen DKG proof
    /// - `encrypted_dkg_share` - Encrypted DKG share
    /// - `pk` - Sender public key
    pub fn receive_dkg_share(
        &mut self,
        poker_table: &PokerTable,
        pedersen_dkg_proof: &PedersenDKGProof,
        encrypted_dkg_share: &EncryptedDKGShare,
        account: &Account,
    ) -> Result<(), ReceiveDKGShareError> {
        if self.received_dkg_shares.get(&account.address).is_some() {
            return Err(ReceiveDKGShareError::AlreadyReceived);
        }

        let ecdh_key = ecdh_key(&self.account.sk, &account.pk)
            .map_err(|_| ReceiveDKGShareError::ECDHSecretFail)?;
        let dkg_share = encrypted_dkg_share
            .decrypt_dkg_share(&ecdh_key.to_bytes_be())
            .map_err(|_| ReceiveDKGShareError::DKGDecryptionFail)?;

        let share_fe = Fe::from_bytes_be(&dkg_share)
            .map_err(|_| ReceiveDKGShareError::InvalidSharedElement)?;

        if pedersen_dkg_proof
            .verify(share_fe, &self.account.address)
            .is_ok()
        {
            self.received_dkg_shares.insert(account.address, share_fe);

            self.secret_dkg_share += share_fe;

            Ok(())
        } else {
            Err(ReceiveDKGShareError::InvalidDKGProof)
        }
    }

    pub fn dkg_shared_pk(&self) -> Option<CurvePoint> {
        if let Some(pedersen_dkg) = &self.pedersen_dkg {
            // if received all the dkg shares
            if self.received_dkg_shares.len() == pedersen_dkg.dkg_shares.len() - 1 {
                return Some(
                    StarkCurve::generator()
                        .operate_with_self(self.secret_dkg_share.representative()),
                );
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::cairo_short_string_to_fe;
    use crate::{
        assets::{
            player::{Account, Player},
            poker_table::{BuyInPokerTableType, PokerTable, PokerTableType, Rake},
        },
        Fe,
    };
    use crypto_bigint::U256;
    use lambdaworks_math::cyclic_group::IsGroup;
    use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
    use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;

    #[test]
    fn test_dkg() {
        let mut poker_table = PokerTable::new(
            PokerTableType::BuyIn(BuyInPokerTableType {
                buy_in: U256::from_u8(10),
            }),
            6,
            3,
            Rake::default(),
        );

        let player1_account = Account::new(Fe::from(10), Fe::from(101));
        let player2_account = Account::new(Fe::from(20), Fe::from(202));
        let player3_account = Account::new(Fe::from(30), Fe::from(303));

        let mut player1 = Player::new(&player1_account);
        let mut player2 = Player::new(&player2_account);
        let mut player3 = Player::new(&player3_account);

        poker_table
            .add_player(
                &player1_account,
                &player1_account.pk,
                U256::from_u128(250),
                None,
            )
            .unwrap();
        poker_table
            .add_player(&player2_account, U256::from_u128(400), None)
            .unwrap();
        poker_table
            .add_player(&player3_account, U256::from_u128(300), None)
            .unwrap();

        let player1_dkg_commitment_hash = player1.run_pedersen_dkg(&poker_table).unwrap();
        let player2_dkg_commitment_hash = player2.run_pedersen_dkg(&poker_table).unwrap();
        let player3_dkg_commitment_hash = player3.run_pedersen_dkg(&poker_table).unwrap();

        poker_table
            .register_dkg_commitment(&player1_dkg_commitment_hash, &player1_account)
            .expect("Fail to register dkg commitment");
        poker_table
            .register_dkg_commitment(&player2_dkg_commitment_hash, &player2_account)
            .expect("Fail to register dkg commitment");
        poker_table
            .register_dkg_commitment(&player3_dkg_commitment_hash, &player3_account)
            .expect("Fail to register dkg commitment");

        player1
            .receive_dkg_share(
                &poker_table,
                &player2.get_pedersen_dkg_proof().unwrap(),
                &player2
                    .get_player_dkg_share(&poker_table, &player1.account)
                    .unwrap(),
                &player2.account,
            )
            .expect("Receive dkg share fail");

        // Don't register dkg share again
        assert!(
            player1
                .receive_dkg_share(
                    &poker_table,
                    &player2.get_pedersen_dkg_proof().unwrap(),
                    &player2
                        .get_player_dkg_share(&poker_table, &player1.account)
                        .unwrap(),
                    &player2.account,
                )
                .is_err()
        );

        player1
            .receive_dkg_share(
                &poker_table,
                &player3.get_pedersen_dkg_proof().unwrap(),
                &player3
                    .get_player_dkg_share(&poker_table, &player1.account)
                    .unwrap(),
                &player3.account,
            )
            .expect("Receive dkg share fail");

        assert!(player1.dkg_shared_pk().is_some());

        player2
            .receive_dkg_share(
                &poker_table,
                &player1.get_pedersen_dkg_proof().unwrap(),
                &player1
                    .get_player_dkg_share(&poker_table, &player2.account)
                    .unwrap(),
                &player1.account,
            )
            .expect("Receive dkg share fail");

        player2
            .receive_dkg_share(
                &poker_table,
                &player3.get_pedersen_dkg_proof().unwrap(),
                &player3
                    .get_player_dkg_share(&poker_table, &player2.account)
                    .unwrap(),
                &player3.account,
            )
            .expect("Receive dkg share fail");

        player3
            .receive_dkg_share(
                &poker_table,
                &player1.get_pedersen_dkg_proof().unwrap(),
                &player1
                    .get_player_dkg_share(&poker_table, &player3.account)
                    .unwrap(),
                &player1.account,
            )
            .expect("Receive dkg share fail");

        player3
            .receive_dkg_share(
                &poker_table,
                &player2.get_pedersen_dkg_proof().unwrap(),
                &player2
                    .get_player_dkg_share(&poker_table, &player3.account)
                    .unwrap(),
                &player2.account,
            )
            .expect("Receive dkg share fail");
    }

    #[test]
    fn test_player_encryption_decryption() {
        let player1_account = Account::new(Fe::from(10), Fe::from(101));
        let player2_account = Account::new(Fe::from(20), Fe::from(202));
        let player3_account = Account::new(Fe::from(30), Fe::from(303));

        let player1 = Player::new(&player1_account);
        let player2 = Player::new(&player2_account);
        let player3 = Player::new(&player3_account);

        let message = cairo_short_string_to_fe("K").unwrap();
        let M = StarkCurve::generator().operate_with_self(message.representative());

        let player1_enc = player1.encrypt(&M);
        let player2_enc = player2.encrypt(&player1_enc);
        let player3_enc = player3.encrypt(&player2_enc);

        // test decryption out of order
        assert_eq!(
            player1.decrypt(&player2.decrypt(&player3.decrypt(&player3_enc))),
            M
        );

        assert_eq!(
            player1.decrypt(&player3.decrypt(&player2.decrypt(&player3_enc))),
            M
        );
        assert_eq!(
            player2.decrypt(&player1.decrypt(&player3.decrypt(&player3_enc))),
            M
        );
        assert_eq!(
            player3.decrypt(&player2.decrypt(&player1.decrypt(&player3_enc))),
            M
        );
    }
}
