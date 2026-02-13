use crate::assets::player::Player;
use starknet::core::types::U256;
use starknet_types_core::{curve::AffinePoint, felt::Felt};

enum PokerTableStatus {
    Waiting,
    Playing,
    Full,
}

enum PokerTableType {
    BuyIn(BuyInPokerTableType),
    Tournament(TournamentPokerTableType),
}

struct BuyInPokerTableType {
    buy_in: U256,
}

/// Tournament Poker Table Type
///
/// - `entry_fee` - Fee charged for tournament registration. Entry fee includes buy-in.
struct TournamentPokerTableType {
    entry_fee: U256,
}

/// Rake.
///
/// - `hand` - commission percent per hand
/// - `game` - commission percent per game
struct Rake {
    hand: Option<RakeFee>,
    game: Option<RakeFee>,
}

/// Rake fee
///
/// - `percent` - Values are multiples of 10. (e.g. 25 = 2.5%).
/// - `capped` - Max value for the rake. 0 means no capped.
struct RakeFee {
    percent: Felt,
    capped: U256,
}

struct ActivePlayer {
    player: Player,
    session_key: AffinePoint,
}

struct PokerTable {
    table_id: Felt,
    current_game_id: Felt,
    table_type: PokerTableType,
    status: PokerTableStatus,
    max_players: usize,
    min_players: usize,
    players: Vec<ActivePlayer>,
    pending_players: Vec<Player>,
    current_deck_hash: Felt,
    rake: Rake,
}
