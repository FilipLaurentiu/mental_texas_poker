use crate::{utils::get_random_fe, CurvePoint, FE};
use crypto_bigint::U256;
use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
use std::collections::HashMap;

pub enum PokerTableStatus {
    Waiting,
    Playing,
    Full,
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

pub struct PokerTable {
    pub table_id: FE,
    pub current_game_id: FE,
    pub table_type: PokerTableType,
    pub status: PokerTableStatus,
    pub max_players: usize,
    pub min_players: usize,
    pub players_addresses: Vec<FE>,
    pub pending_players_addresses: Vec<FE>,
    pub players_pub_keys: HashMap<FE, (FE, FE)>,
    pub players_funds: HashMap<FE, U256>,
    pub current_deck_hash: Option<FE>,
    pub rake: Rake,
}

#[derive(Debug)]
pub enum NewPlayerError {
    FullTable,
    InvalidSignature,
    FundingError,
}
impl PokerTable {
    pub(crate) fn new(
        table_type: PokerTableType,
        max_players: usize,
        min_players: usize,
        rake: Rake,
    ) -> Self {
        Self {
            table_id: get_random_fe(),
            current_game_id: FE::zero(),
            table_type,
            status: PokerTableStatus::Waiting,
            max_players,
            min_players,
            players_addresses: vec![],
            pending_players_addresses: vec![],
            players_pub_keys: HashMap::new(),
            players_funds: HashMap::new(),
            current_deck_hash: None,
            rake,
        }
    }

    /// Add new player.
    /// Returns the table seat of the player.
    pub fn add_player(
        &mut self,
        player: &FE,
        pub_key: &CurvePoint,
        buy_in: U256,
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
                let table_position = self.register_player(player, buy_in, pub_key);

                // game could start if enough players are in the waiting queue
                if self.pending_players_addresses.len() == self.min_players {
                    self.status = PokerTableStatus::Playing;
                    self.start_game();
                }
                Ok(table_position)
            }
            PokerTableStatus::Playing => Ok(self.register_player(player, buy_in, pub_key)),
            PokerTableStatus::Full => Err(NewPlayerError::FullTable),
        }
    }
    fn register_player(&mut self, player: &FE, buy_in: U256, pub_key: &CurvePoint) -> usize {
        self.pending_players_addresses.push(*player);
        self.players_funds.insert(*player, buy_in);
        self.players_pub_keys
            .insert(*player, (*pub_key.x(), *pub_key.y()));
        self.transfer_player_funds(player, buy_in);

        self.players_addresses.len()
    }

    pub fn leave_table() {
        unimplemented!()
    }

    pub fn get_active_players(&self) -> &[FE] {
        &self.players_addresses
    }

    pub fn start_game(&mut self) {
        // generate new unique game id
        self.current_game_id = PedersenStarkCurve::hash(&self.current_game_id, &get_random_fe());
    }

    fn transfer_player_funds(&self, player: &FE, buy_in: U256) {}
}
