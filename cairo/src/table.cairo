use bool::True;
use starknet::ContractAddress;
use starknet::storage::{Map, MutableVecTrait, Vec};

#[derive(starknet::Store, Drop, Serde)]
#[allow(starknet::store_no_default_variant)]
pub enum PokerTableType {
    BuyIn: BuyInPokerTableType,
    Tournament: TournamentPokerTableType,
}

#[derive(starknet::Store, Drop, Serde)]
pub struct BuyInPokerTableType {
    pub buy_in: u256,
}

/// Tournament Poker Table Type
///
/// - `entry_fee` - Fee charged for tournament registration. Entry fee includes buy-in.
#[derive(starknet::Store, Drop, Serde)]
pub struct TournamentPokerTableType {
    pub entry_fee: u256,
}


#[derive(starknet::Store, Drop, Serde, PartialEq)]
pub enum PokerTableStatus {
    #[default]
    Uninitialized,
    Waiting,
    Playing: PokerTableStatusPlaying,
}

#[derive(starknet::Store, Drop, Serde, PartialEq)]
pub enum PokerTableStatusPlaying {
    #[default]
    DealingCards,
}


/// Rake fee
///
/// - `percent` - Values are multiples of 10. (e.g. 25 = 2.5%).
/// - `capped` - Max value for the rake. 0 means no capped.
#[derive(starknet::Store, Drop, Serde)]
pub struct RakeFee {
    pub percent: felt252,
    pub capped: u256,
}

/// Rake.
///
/// - `hand` - commission percent per hand
/// - `game` - commission percent per game
///
#[derive(starknet::Store, Drop, Serde)]
pub enum RakeType {
    #[default]
    hand: RakeFee,
    game: RakeFee,
}

#[starknet::storage_node]
pub struct PokerTable {
    pub status: PokerTableStatus,
    pub table_type: PokerTableType,
    pub rake: RakeType,
    pub max_players: u64,
    pub min_players: u64,
    pub game_id: felt252,
    pub dealer_index: usize,
    pub players_funds: Map<ContractAddress, u256>,
    pub player_seat: Map<ContractAddress, u64>,
    pub active_players: Vec<ContractAddress>,
    pub pending_players: Vec<ContractAddress>,
    pub token: ContractAddress
}
