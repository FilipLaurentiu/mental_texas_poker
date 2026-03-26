use crate::table::{PokerTable, PokerTableStatus, PokerTableType, RakeType};

#[starknet::interface]
pub trait IMentalPoker<TContractState> {
    /// Create new poker table.
    fn new_table(
        ref self: TContractState,
        table_type: PokerTableType,
        max_players: u64,
        min_players: u64,
        rake: RakeType,
    );


    fn join_table(
        ref self: TContractState,
        table_id: felt252,
        game_key: felt252,
        buy_in: u256,
        seat: Option<usize>,
    ) -> Result<u64, felt252>;

    /// Retrieve poker table details.
    fn get_table_status(self: @TContractState, table_id: felt252) -> PokerTableStatus;
    fn get_table_type(self: @TContractState, table_id: felt252) -> PokerTableType;
}
