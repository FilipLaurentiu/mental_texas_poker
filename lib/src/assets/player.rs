use crate::{
    assets::{
        card::Card,
        poker_table::{PokerTable, PokerTableStatus, PokerTableStatusPlaying},
    }, crypto::{
        ecdh::ecdh_secret,
        ecdsa::EcdsaSignature,
        pedersen_dkg::{EncryptedDKGShare, PedersenDKG, PedersenDKGProof},
        pedersen_hash::hash_array,
        utils::new_ec_from_x,
    },
    CurvePoint,
    FE
    ,
};
use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    traits::ByteConversion,
};
use std::{cmp::PartialEq, collections::HashMap, task::Wake};

pub struct Account {
    pub address: FE,
    pub pk: FE,
    sk: FE,
}

impl Account {
    pub fn new(address: FE, sk: FE) -> Self {
        let pub_key = StarkCurve::generator().operate_with_self(sk.representative());
        Self {
            address,
            pk: *pub_key.x(),
            sk,
        }
    }

    pub fn is_valid_signature(&self, hash: FE, signature: &[FE]) -> bool {
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

/// - `wallet` - on-chain wallet address
/// - `secret_key_share` - share of the distributed key
/// - `encrypted_cards` - encrypted cards that player owns
pub struct Player<'a> {
    table_seat: Option<usize>,
    pub account: &'a Account,
    encrypted_cards: Option<[CurvePoint; 2]>,
    decrypted_cards: Option<[Card; 2]>,
    pedersen_dkg: Option<PedersenDKG>,
    secret_key_share: Option<FE>,
    dkg_shares: Vec<FE>,
    received_dkg_shares: HashMap<FE, bool>,
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
    MissingPedersenDKG,
    UnfinishedPedersenDKG,
    InvalidPedersenDKG,
    InvalidTableSeat,
}

#[derive(Debug)]
pub enum RunPedersenDKGError {
    InvalidTableStatus,
    InvalidTable,
}

pub struct DKGCommitment {
    pub commitment_hash: FE,
    pub signature: EcdsaSignature,
}

impl<'a> Player<'a> {
    fn new(account: &'a Account) -> Self {
        Self {
            account,
            table_seat: None,
            encrypted_cards: None,
            decrypted_cards: None,
            pedersen_dkg: None,
            secret_key_share: None,
            dkg_shares: vec![],
            received_dkg_shares: HashMap::new(),
        }
    }

    /// Get the public key of the player.
    pub fn pub_key(&self) -> &FE {
        &self.account.pk
    }

    /// Run Pedersen DKG.
    pub fn run_pedersen_dkg(&mut self, table: &PokerTable) -> Result<FE, RunPedersenDKGError> {
        let pedersen_dkg = PedersenDKG::new(
            table.players_addresses.len(),
            &self.account.sk,
            &table.players_addresses,
        );

        let commitment_hash: FE = hash_array(
            &pedersen_dkg
                .proof
                .commitments
                .iter()
                .map(|point| {
                    (PedersenStarkCurve::hash(point.to_affine().x(), point.to_affine().y()))
                })
                .collect::<Vec<FE>>(),
        );

        self.pedersen_dkg = Some(pedersen_dkg);

        Ok(commitment_hash)
    }

    /// Get Encrypted partial DKG share for the specific user
    pub fn get_player_dkg_share(
        &self,
        table: &PokerTable,
        address: &FE,
    ) -> Result<&EncryptedDKGShare, GetPlayerDKGShareError> {
        if table.status != PokerTableStatus::Playing(PokerTableStatusPlaying::PedersenDKGCommitmentsRegistered) {
            return Err(GetPlayerDKGShareError::UnfinishedPedersenDKG);
        }

        if self.account.address == *address {
            return Err(GetPlayerDKGShareError::InvalidTableSeat);
        }
        if let Some(table_seat) = table.get_player_seat(address) {
            Ok(self
                .pedersen_dkg
                .as_ref()
                .ok_or_else(|| GetPlayerDKGShareError::InvalidPedersenDKG)?
                .encrypted_dkg_shares
                .get(*table_seat)
                .ok_or_else(|| GetPlayerDKGShareError::InvalidTableSeat)?)
        } else {
            Err(GetPlayerDKGShareError::InvalidTableSeat)
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
        pk: &FE,
    ) -> Result<(), ReceiveDKGShareError> {
        if let Some(received) = self.received_dkg_shares.get(pk) {
            if *received {
                return Err(ReceiveDKGShareError::AlreadyReceived);
            }
        }

        let ecdh_secret = ecdh_secret(&self.account.pk, pk)
            .unwrap()
            .to_bytes_be();
        let dkg_share = encrypted_dkg_share
            .decrypt_dkg_share(&ecdh_secret)
            .map_err(|_| ReceiveDKGShareError::DKGDecryptionFail)?;

        let share_fe =
            FE::from_bytes_be(&dkg_share).map_err(|_| ReceiveDKGShareError::InvalidShareElement)?;

        if pedersen_dkg_proof.verify(share_fe, pk) {
            self.dkg_shares.push(share_fe);
            self.received_dkg_shares.insert(*pk, true);
            Ok(())
        } else {
            Err(ReceiveDKGShareError::InvalidDKGProof)
        }
    }

    pub fn dkg_share(&self) -> FE {
        // sum of dkg shares from other players
        let dkg_shares_sum: FE = self.dkg_shares.iter().fold(FE::zero(), |a, b| a + b);

        dkg_shares_sum + self.secret_key_share.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        assets::{
            player::{Account, Player},
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
            3,
            Rake::default(),
        );

        let player1_account = Account::new(FE::from(1), FE::from(101));
        let player2_account = Account::new(FE::from(2), FE::from(202));
        let player3_account = Account::new(FE::from(3), FE::from(303));

        let mut player1 = Player::new(&player1_account);
        let mut player2 = Player::new(&player2_account);
        let mut player3 = Player::new(&player3_account);

        poker_table
            .add_player(&player1.account.address, U256::from_u128(250), None)
            .unwrap();
        poker_table
            .add_player(&player2.account.address, U256::from_u128(400), None)
            .unwrap();
        poker_table
            .add_player(&player3.account.address, U256::from_u128(300), None)
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
                &player2.get_pedersen_dkg_proof().unwrap(),
                player2
                    .get_player_dkg_share(&poker_table, &player1.account.address)
                    .unwrap(),
                &player2.pub_key(),
            )
            .unwrap();

        player1
            .receive_dkg_share(
                &player3.get_pedersen_dkg_proof().unwrap(),
                player3
                    .get_player_dkg_share(&poker_table, &player1.account.address)
                    .unwrap(),
                &player3.pub_key(),
            )
            .unwrap();
    }
}
