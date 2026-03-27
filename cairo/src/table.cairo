use bool::True;
use starknet::ContractAddress;
use starknet::storage::{Map, MutableVecTrait, Vec};

#[derive(starknet::Store, Drop, Serde, Default)]
#[allow(starknet::store_no_default_variant)]
pub enum PokerTableType {
    #[default]
    BuyIn: BuyInPokerTableType,
    Tournament: TournamentPokerTableType,
}

#[derive(starknet::Store, Drop, Serde, Default)]
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


#[derive(starknet::Store, Drop, Serde, Default, PartialEq)]
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
#[derive(starknet::Store, Drop, Serde, Default)]
pub struct RakeFee {
    pub percent: felt252,
    pub capped: u256,
}

/// Rake.
///
/// - `hand` - commission percent per hand
/// - `game` - commission percent per game
///
#[derive(starknet::Store, Drop, Serde, Default)]
pub enum RakeType {
    #[default]
    hand: RakeFee,
    game: RakeFee,
}

#[starknet::storage_node]
pub struct PokerTablePlayersInfo {
    pub players_funds: Map<ContractAddress, u256>,
    pub player_seat: Map<ContractAddress, u64>,
    pub active_players: Vec<ContractAddress>,
    pub pending_players: Vec<ContractAddress>,
}

/// all 52 positions are publicly available in the beginning
const COMMUNITY_CARDS_DEFAULT_AVAILABILITY: u64 =
    0b1111111111111111111111111111111111111111111111111111;


#[derive(starknet::Store, Drop)]
pub struct PokerTable {
    pub status: PokerTableStatus,
    pub table_type: PokerTableType,
    pub rake: RakeType,
    pub max_players: u64,
    pub min_players: u64,
    pub game_id: felt252,
    pub dealer_index: usize,
    pub token: ContractAddress,
    pub community_cards_availability: u64,
}


pub impl PokerTableDefault of Default<PokerTable> {
    fn default() -> PokerTable {
        PokerTable {
            status: PokerTableStatusDefault::default(),
            table_type: PokerTableTypeDefault::default(),
            rake: RakeTypeDefault::default(),
            max_players: 10,
            min_players: 2,
            game_id: 0,
            dealer_index: 0,
            token: 0.try_into().unwrap(),
            community_cards_availability: COMMUNITY_CARDS_DEFAULT_AVAILABILITY,
        }
    }
}


#[generate_trait]
pub impl PokerTableImpl of PokerTableTrait {
    fn new(
        table_type: PokerTableType,
        max_players: u64,
        min_players: u64,
        rake: RakeType,
        token: ContractAddress,
    ) -> PokerTable {
        PokerTable {
            status: PokerTableStatusDefault::default(),
            table_type,
            rake,
            max_players,
            min_players,
            game_id: 0,
            dealer_index: 0,
            token,
            community_cards_availability: COMMUNITY_CARDS_DEFAULT_AVAILABILITY,
        }
    }
}
