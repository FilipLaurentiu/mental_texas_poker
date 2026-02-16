use crate::assets::player::Player;
use crate::FE;
use starknet::core::types::U256;

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
    percent: FE,
    capped: U256,
}

struct PokerTable {
    table_id: FE,
    current_game_id: FE,
    table_type: PokerTableType,
    status: PokerTableStatus,
    max_players: usize,
    min_players: usize,
    players: Vec<Player>,
    pending_players: Vec<Player>,
    current_deck_hash: FE,
    rake: Rake,
}

enum NewPlayerError {
    FullTable,
    InvalidSignature,
    FundingError,
}
impl PokerTable {
    fn new() -> Self {
        todo!()
    }

    /// Add new player.
    /// Returns the table seat of the player.
    pub fn add_player(mut self, player: Player, buy_in: U256, signature: FE) -> Result<usize, NewPlayerError> {
        /// TODO: Verify player signature && transfer funds
        match self.status {
            PokerTableStatus::Waiting => {
                self.pending_players.push(player);
                // game could start if enough players are in the waiting queue
                if self.pending_players.len() == self.min_players {
                    self.status = PokerTableStatus::Playing;
                }
                Ok(self.players.len())
            }
            PokerTableStatus::Playing => {
                self.pending_players.push(player);
                Ok(self.players.len())
            }
            PokerTableStatus::Full => Err(NewPlayerError::FullTable),
        }
    }
}
