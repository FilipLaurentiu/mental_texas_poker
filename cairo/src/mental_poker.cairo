#[starknet::contract]
mod MentalPoker {
    use cairo_mental_poker::interfaces::IMentalPoker;
    use core::hash::{HashStateExTrait, HashStateTrait};
    use core::poseidon::{PoseidonTrait, poseidon_hash_span};
    use openzeppelin::interfaces::account::accounts::AccountABIDispatcher;
    use openzeppelin::interfaces::erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
    use starknet::storage::{
        Map, Mutable, MutableVecTrait, StorageMapReadAccess, StoragePath, StoragePathEntry,
        StoragePointerReadAccess, StoragePointerWriteAccess, Vec, VecTrait,
    };
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address, get_execution_info, get_tx_info,
    };
    use crate::table::{
        PokerTable, PokerTableDefault, PokerTableImpl, PokerTablePlayersInfo, PokerTableStatus,
        PokerTableStatusPlaying, PokerTableTrait, PokerTableType, RakeType,
    };

    #[storage]
    struct Storage {
        poker_tables: Map<felt252, PokerTable>,
        poker_table_players: Map<felt252, PokerTablePlayersInfo>,
        token_address: ContractAddress,
        poker_tables_count: felt252,
    }

    pub mod Errors {
        pub const TABLE_ALREADY_EXIST: felt252 = 'New Table: Already exist';
        pub const NOT_ENOUGH_FUNDS: felt252 = 'Join table: Not enough funds';
        pub const FULL_TABLE: felt252 = 'Join table: Table is full';
        pub const ALREADY_REGISTERED: felt252 = 'Join table: Already registered';
        pub const INVALID_TABLE: felt252 = 'Invalid table id';
    }


    #[constructor]
    fn constructor(ref self: ContractState, token_address: ContractAddress) {
        self.token_address.write(token_address);
    }

    #[abi(embed_v0)]
    impl MentalPokerImpl of IMentalPoker<ContractState> {
        fn get_table_status(self: @ContractState, table_id: felt252) -> PokerTableStatus {
            self.poker_tables.entry(table_id).status.read()
        }

        fn get_table_type(self: @ContractState, table_id: felt252) -> PokerTableType {
            self.poker_tables.entry(table_id).table_type.read()
        }

        fn is_full(self: @ContractState, table_id: felt252) -> core::bool {
            self.poker_table_players.entry(table_id).pending_players.len()
                + self
                    .poker_table_players
                    .entry(table_id)
                    .active_players
                    .len() == self
                    .poker_tables
                    .entry(table_id)
                    .max_players
                    .read()
        }

        fn new_table(
            ref self: ContractState,
            table_type: PokerTableType,
            max_players: u64,
            min_players: u64,
            rake: RakeType,
        ) {
            let table_id = self.generate_new_table_id();

            assert(
                self.poker_tables.entry(table_id).status.read() != PokerTableStatus::Uninitialized,
                Errors::TABLE_ALREADY_EXIST,
            );

            let token_address = self.token_address.read();

            let poker_table = PokerTableTrait::new(
                table_type, max_players, min_players, rake, token_address,
            );

            self.poker_tables.entry(table_id).write(poker_table);
            self.poker_tables_count.write(self.poker_tables_count.read() + 1);
        }

        fn join_table(
            ref self: ContractState, table_id: felt252, buy_in: u256, seat: Option<usize>,
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

            let poker_table_players = self.poker_table_players.entry(table_id);

            match poker_table.status.read() {
                PokerTableStatus::Uninitialized => Err(Errors::INVALID_TABLE),
                PokerTableStatus::Waiting => {
                    if self.is_pending_player(table_id, caller) {
                        return Err(Errors::ALREADY_REGISTERED);
                    }

                    self.register_player(table_id, buy_in, seat);

                    // game could start if enough players are in the waiting queue
                    if poker_table_players.pending_players.len() == poker_table.min_players.read() {
                        self.start_game(table_id);
                    }

                    Result::Ok(poker_table_players.active_players.len())
                },
                PokerTableStatus::Playing(_) => {
                    if self.is_full(table_id) {
                        return Err(Errors::FULL_TABLE);
                    }

                    if self.is_active_player(table_id, caller)
                        || self.is_pending_player(table_id, caller) {
                        return Err(Errors::ALREADY_REGISTERED);
                    }

                    self.register_player(table_id, buy_in, seat);

                    let table_position = poker_table_players.pending_players.len()
                        + poker_table_players.active_players.len();

                    Result::Ok(table_position)
                },
            }
        }

        fn flop(ref self: ContractState, table_id: felt252) {}
        fn turn(ref self: ContractState, table_id: felt252) {}
        fn river(ref self: ContractState, table_id: felt252) {}
    }


    #[generate_trait]
    impl MentalPokerInternalImpl of MentalPokerInternalTrait {
        fn register_player(
            ref self: ContractState, table_id: felt252, buy_in: u256, seat: Option<usize>,
        ) {
            let caller = get_caller_address();
            let poker_table_players = self.poker_table_players.entry(table_id);
            poker_table_players.pending_players.push(caller);
            poker_table_players.players_funds.entry(caller).write(buy_in);

            if let Some(_seat_preference) = seat { // TODO
            } else {
                let next_available_seat = poker_table_players.active_players.len()
                    + poker_table_players.pending_players.len();

                poker_table_players.player_seat.entry(caller).write(next_available_seat);
            }

            let token = ERC20ABIDispatcher { contract_address: self.token_address.read() };
            let this = get_contract_address();

            token.transfer_from(caller, this, buy_in);
        }


        fn is_pending_player(
            ref self: ContractState, table_id: felt252, player: ContractAddress,
        ) -> core::bool {
            let poker_table_players = self.poker_table_players.entry(table_id);
            let pending_players_len = poker_table_players.pending_players.len();

            for i in 0..pending_players_len {
                if poker_table_players.pending_players.at(i).read() == player {
                    return true;
                };
            }
            false
        }

        fn is_active_player(
            ref self: ContractState, table_id: felt252, player: ContractAddress,
        ) -> core::bool {
            let poker_table_players = self.poker_table_players.entry(table_id);
            let active_players_len = poker_table_players.active_players.len();

            for i in 0..active_players_len {
                if poker_table_players.active_players.at(i).read() == player {
                    return true;
                };
            }
            false
        }

        fn start_game(ref self: ContractState, table_id: felt252) {
            let poker_table = self.poker_tables.entry(table_id);
            let poker_table_players = self.poker_table_players.entry(table_id);

            for i in 0..poker_table.min_players.read() {
                let pending_player_mem_slot = poker_table_players.pending_players.at(i);
                poker_table_players.active_players.at(i).write(pending_player_mem_slot.read());
                pending_player_mem_slot.write(0.try_into().unwrap());
            }

            poker_table
                .status
                .write(PokerTableStatus::Playing(PokerTableStatusPlaying::DealingCards))
        }


        /// generate unique table id
        fn generate_new_table_id(ref self: ContractState) -> felt252 {
            let execution_info = get_execution_info();

            let table_id = poseidon_hash_span(
                array![
                    execution_info.tx_info.transaction_hash,
                    execution_info.caller_address.try_into().unwrap(),
                    self.poker_tables_count.read(),
                ]
                    .span(),
            );

            table_id
        }
    }
}
