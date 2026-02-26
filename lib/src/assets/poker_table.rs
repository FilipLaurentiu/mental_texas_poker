use crate::{assets::player::Account, utils::get_random_fe, FE};
use crypto_bigint::U256;
use std::collections::HashMap;

#[derive(Eq, PartialEq)]
pub enum PokerTableStatus {
    Waiting,
    Playing(PokerTableStatusPlaying),
    Full,
}

#[derive(Eq, PartialEq)]
pub enum PokerTableStatusPlaying {
    PedersenDKGStarted,
    PedersenDKGCommitmentsRegistered,
    PedersenDKGEnded,
}

pub enum PokerTableType {
    BuyIn(BuyInPokerTableType),
    Tournament(TournamentPokerTableType),
}

pub struct BuyInPokerTableType {
    pub(crate) buy_in: U256,
}

/// Tournament Poker Table Type
///
/// - `entry_fee` - Fee charged for tournament registration. Entry fee includes buy-in.
pub struct TournamentPokerTableType {
    entry_fee: U256,
}

/// Rake.
///
/// - `hand` - commission percent per hand
/// - `game` - commission percent per game
///
#[derive(Default)]
pub struct Rake {
    hand: Option<RakeFee>,
    game: Option<RakeFee>,
}

/// Rake fee
///
/// - `percent` - Values are multiples of 10. (e.g. 25 = 2.5%).
/// - `capped` - Max value for the rake. 0 means no capped.
pub struct RakeFee {
    percent: FE,
    capped: U256,
}

pub struct PokerTable<'a> {
    pub table_id: FE,
    pub table_type: PokerTableType,
    pub status: PokerTableStatus,
    pub rake: Rake,
    pub max_players: usize,
    pub min_players: usize,
    pub players_accounts: Vec<&'a Account>,
    pub pending_players_accounts: Vec<&'a Account>,
    pub players_funds: HashMap<FE, U256>,
    pub game_id: FE,
    pub current_deck_hash: Option<FE>,
    // address -> commitment hash
    pub dkg_commitments: HashMap<FE, FE>,
    // address to seat
    pub player_seat: HashMap<FE, usize>,
}

impl<'a> Default for PokerTable<'a> {
    fn default() -> Self {
        Self {
            table_id: Default::default(),
            table_type: PokerTableType::BuyIn(BuyInPokerTableType {
                buy_in: U256::from_u8(0),
            }),
            status: PokerTableStatus::Waiting,
            max_players: 10,
            min_players: 2,
            pending_players_accounts: vec![],
            players_funds: Default::default(),
            game_id: Default::default(),
            current_deck_hash: None,
            dkg_commitments: Default::default(),
            players_accounts: vec![],
            rake: Default::default(),
            player_seat: Default::default(),
        }
    }
}

#[derive(Debug)]
pub enum NewPlayerError {
    FullTable,
    InvalidSignature,
    FundingError,
    AlreadyRegistered,
}

#[derive(Debug)]
pub enum RegisterDKGCommitmentError {
    InvalidActivePlayer,
    InvalidPedersenDKGStatus,
    AlreadyRegistered,
}

impl<'a> PokerTable<'a> {
    pub(crate) fn new(
        table_type: PokerTableType,
        max_players: usize,
        min_players: usize,
        rake: Rake,
    ) -> Self {
        Self {
            table_id: get_random_fe(),
            table_type,
            max_players,
            min_players,
            rake,
            ..Default::default()
        }
    }

    /// Add new player.
    /// Returns the table seat of the player.
    pub fn add_player(
        &mut self,
        account: &'a Account,
        buy_in: U256,
        seat: Option<usize>,
    ) -> Result<usize, NewPlayerError> {
        match &self.table_type {
            PokerTableType::BuyIn(buy_in_table) => {
                if buy_in_table.buy_in > buy_in {
                    return Err(NewPlayerError::FundingError);
                }
            }
            PokerTableType::Tournament(tournament_table) => {
                if tournament_table.entry_fee > buy_in {
                    return Err(NewPlayerError::FundingError);
                }
            }
        }
        match self.status {
            PokerTableStatus::Waiting => {
                if self.pending_players_accounts.contains(&account) {
                    return Err(NewPlayerError::AlreadyRegistered);
                }

                self.register_player(account, buy_in, seat);

                // game could start if enough players are in the waiting queue
                if self.pending_players_accounts.len() == self.min_players {
                    self.status =
                        PokerTableStatus::Playing(PokerTableStatusPlaying::PedersenDKGStarted);
                    self.start_game();
                }

                Ok(self.players_accounts.len())
            }
            PokerTableStatus::Playing(_) => {
                if self.players_accounts.contains(&account)
                    || self.pending_players_accounts.contains(&account)
                {
                    return Err(NewPlayerError::AlreadyRegistered);
                }

                self.register_player(account, buy_in, seat);

                let table_position =
                    self.pending_players_accounts.len() + self.players_accounts.len();

                Ok(table_position)
            }
            PokerTableStatus::Full => Err(NewPlayerError::FullTable),
        }
    }
    fn register_player(&mut self, account: &'a Account, buy_in: U256, seat: Option<usize>) {
        let account_address = account.address.clone();
        self.pending_players_accounts.push(account);
        self.players_funds.insert(account_address, buy_in);

        if let Some(_seat_preference) = seat {
            todo!()
        } else {
            let next_available_seat =
                self.players_accounts.len() + self.pending_players_accounts.len();
            self.player_seat
                .insert(account_address, next_available_seat);
        }

        self.transfer_from(&account_address, buy_in);
    }

    /// Register DKG commitment.
    pub fn register_dkg_commitment(
        &mut self,
        dkg_commitment_hash: &FE,
        sender: &Account,
    ) -> Result<(), RegisterDKGCommitmentError> {
        if self.status != PokerTableStatus::Playing(PokerTableStatusPlaying::PedersenDKGStarted) {
            return Err(RegisterDKGCommitmentError::InvalidPedersenDKGStatus);
        }

        if let Some(_) = self.dkg_commitments.get(&sender.address) {
            return Err(RegisterDKGCommitmentError::AlreadyRegistered);
        }

        if !self.players_accounts.contains(&sender) {
            return Err(RegisterDKGCommitmentError::InvalidActivePlayer);
        }

        self.dkg_commitments
            .insert(sender.address, *dkg_commitment_hash);

        // all commitments are registered
        if self.dkg_commitments.len() == self.players_accounts.len() {
            self.status = PokerTableStatus::Playing(
                PokerTableStatusPlaying::PedersenDKGCommitmentsRegistered,
            );
        }

        Ok(())
    }

    /// Get player seat at the table from their address.
    pub fn get_player_seat(&self, address: &FE) -> Option<&usize> {
        self.player_seat.get(address)
    }

    pub fn leave_table() {
        unimplemented!()
    }

    pub fn get_active_players(&self) -> &Vec<&'a Account> {
        &self.players_accounts
    }

    pub fn start_game(&mut self) {
        // pending players are now active
        self.players_accounts = self.pending_players_accounts.clone();

        // empty pending players list
        self.pending_players_accounts = vec![];

        self.status = PokerTableStatus::Playing(PokerTableStatusPlaying::PedersenDKGStarted);
    }

    fn transfer_from(&self, address: &FE, buy_in: U256) {}
}
