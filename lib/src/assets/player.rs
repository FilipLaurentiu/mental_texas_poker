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
    FE,
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    traits::ByteConversion,
};
use std::{cmp::PartialEq, collections::HashMap};

#[derive(PartialEq, Clone, Eq, Hash)]
pub struct Account {
    pub address: FE,
    pub pk: FE,
    sk: FE,
}

impl Account {
    pub fn new(address: FE, sk: FE) -> Self {
        let pub_key = StarkCurve::generator()
            .operate_with_self(sk.representative())
            .to_affine();
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

/// - `account` - on-chain account\
/// - `encrypted_cards` - encrypted cards that player owns
/// - `decrypted_cards` - decrypted cards
/// - `pedersen_dkg` - Pedersen DKG share
/// - `secret_dkg_share` - share of the distributed key
pub struct Player<'a> {
    account: &'a Account,
    encrypted_cards: Option<[CurvePoint; 2]>,
    decrypted_cards: Option<[Card; 2]>,
    pedersen_dkg: Option<PedersenDKG>,
    secret_dkg_share: FE,
    dkg_shares: Vec<FE>,
    // address -> share
    received_dkg_shares: HashMap<FE, FE>,
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
    pub commitment_hash: FE,
    pub signature: EcdsaSignature,
}

impl<'a> Player<'a> {
    fn new(account: &'a Account) -> Self {
        Self {
            account,
            encrypted_cards: None,
            decrypted_cards: None,
            pedersen_dkg: None,
            secret_dkg_share: FE::zero(),
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

        let share_fe = FE::from_bytes_be(&dkg_share)
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

        let player1_account = Account::new(FE::from(10), FE::from(101));
        let player2_account = Account::new(FE::from(20), FE::from(202));
        let player3_account = Account::new(FE::from(30), FE::from(303));

        let mut player1 = Player::new(&player1_account);
        let mut player2 = Player::new(&player2_account);
        let mut player3 = Player::new(&player3_account);

        poker_table
            .add_player(&player1_account, U256::from_u128(250), None)
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
}
