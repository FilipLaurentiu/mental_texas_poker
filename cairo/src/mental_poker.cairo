#[starknet::contract]
mod MentalPoker {
    use cairo_mental_poker::interfaces::IMentalPoker;
    use core::hash::{HashStateExTrait, HashStateTrait};
    use core::poseidon::{PoseidonTrait, poseidon_hash_span};
    use starknet::storage::{
        Map, Mutable, MutableVecTrait, StorageMapReadAccess, StoragePath, StoragePathEntry,
        StoragePointerReadAccess, StoragePointerWriteAccess, Vec,
    };
    use starknet::{ContractAddress, get_caller_address, get_contract_address, get_tx_info};
    use crate::table::{
        PokerTable, PokerTableStatus, PokerTableStatusPlaying, PokerTableType, RakeType,
    };

    #[storage]
    struct Storage {
        poker_tables: Map<felt252, PokerTable>,
    }

    pub mod Errors {
        pub const TABLE_ALREADY_EXIST: felt252 = 'New Table: Already exist';
        pub const NOT_ENOUGH_FUNDS: felt252 = 'Join table: Not enough funds';
        pub const FULL_TABLE: felt252 = 'Join table: Table is full';
        pub const ALREADY_REGISTERED: felt252 = 'Join table: Already registered';
        pub const INVALID_TABLE: felt252 = 'Invalid table id';
    }

    #[abi(embed_v0)]
    impl MentalPokerImpl of IMentalPoker<ContractState> {
        fn new_table(
            ref self: ContractState,
            table_type: PokerTableType,
            max_players: u64,
            min_players: u64,
            rake: RakeType,
        ) {
            let table_id = generate_table_id();

            let poker_table = self.poker_tables.entry(table_id);
            assert(
                poker_table.status.read() != PokerTableStatus::Uninitialized,
                Errors::TABLE_ALREADY_EXIST,
            );

            poker_table.table_type.write(table_type);
            poker_table.max_players.write(max_players);
            poker_table.min_players.write(min_players);
            poker_table.rake.write(rake);
            poker_table.status.write(PokerTableStatus::Waiting);
        }

        fn join_table(
            ref self: ContractState,
            table_id: felt252,
            game_key: felt252,
            buy_in: u256,
            seat: Option<usize>,
        ) -> Result<u64, felt252> {
            let caller = get_caller_address();

            let poker_table = self.poker_tables.entry(table_id);

            match poker_table.table_type.read() {
                PokerTableType::BuyIn(buy_in_table) => {
                    if buy_in_table.buy_in > buy_in {
                        return Err(Errors::NOT_ENOUGH_FUNDS);
                    }
                },
                PokerTableType::Tournament(tournament_table) => {
                    if tournament_table.entry_fee > buy_in {
                        return Err(Errors::NOT_ENOUGH_FUNDS);
                    }
                },
            }

            match poker_table.status.read() {
                PokerTableStatus::Uninitialized => Err(Errors::INVALID_TABLE),
                PokerTableStatus::Waiting => {
                    if self.is_pending_player(table_id, caller) {
                        return Err(Errors::ALREADY_REGISTERED);
                    }

                    self.register_player(caller, game_key, buy_in, seat);

                    // game could start if enough players are in the waiting queue
                    if poker_table.pending_players.len() == poker_table.min_players.read() {
                        poker_table
                            .status
                            .write(PokerTableStatus::Playing(PokerTableStatusPlaying::Playing));
                        self.start_game();
                    }

                    Result::Ok(poker_table.active_players.len())
                },
                PokerTableStatus::Playing(_) => {
                    if self.is_full(table_id) {
                        return Err(Errors::FULL_TABLE);
                    }

                    if self.is_active_player(table_id, caller)
                        || self.is_pending_player(table_id, caller) {
                        return Err(Errors::ALREADY_REGISTERED);
                    }

                    self.register_player(caller, game_key, buy_in, seat);

                    let table_position = poker_table.pending_players.len()
                        + poker_table.active_players.len();

                    Result::Ok(table_position)
                },
            }
        }


        fn get_table_status(self: @ContractState, table_id: felt252) -> PokerTableStatus {
            self.poker_tables.entry(table_id).status.read()
        }
        fn get_table_type(self: @ContractState, table_id: felt252) -> PokerTableType {
            self.poker_tables.entry(table_id).table_type.read()
        }
    }


    #[generate_trait]
    impl MentalPokerInternalImpl of MentalPokerInternalTrait {
        fn register_player(
            ref self: ContractState,
            account: ContractAddress,
            game_key: felt252,
            buy_in: u256,
            seat: Option<usize>,
        ) {}
        fn is_full(ref self: ContractState, table_id: felt252) -> core::bool {
            self.poker_tables.entry(table_id).pending_players.len()
                + self
                    .poker_tables
                    .entry(table_id)
                    .active_players
                    .len() == self
                    .poker_tables
                    .entry(table_id)
                    .max_players
                    .read()
        }

        fn is_pending_player(
            ref self: ContractState, table_id: felt252, player: ContractAddress,
        ) -> core::bool {
            let poker_table = self.poker_tables.entry(table_id);
            let pending_players_len = poker_table.pending_players.len();

            for i in 0..pending_players_len {
                if poker_table.pending_players.at(i).read() == player {
                    return true;
                };
            }
            false
        }

        fn is_active_player(
            ref self: ContractState, table_id: felt252, player: ContractAddress,
        ) -> core::bool {
            let poker_table = self.poker_tables.entry(table_id);

            let active_players_len = poker_table.active_players.len();
            for i in 0..active_players_len {
                if poker_table.active_players.at(i).read() == player {
                    return true;
                };
            }
            false
        }

        fn start_game(ref self: ContractState) {}
    }


    /// generate unique table id
    fn generate_table_id() -> felt252 {
        let caller = get_caller_address();
        let tx_info = get_tx_info();

        let table_id = poseidon_hash_span(
            array![tx_info.transaction_hash, caller.try_into().unwrap()].span(),
        );

        table_id
    }
}
