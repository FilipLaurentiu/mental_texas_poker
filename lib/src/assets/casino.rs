use crate::{assets::poker_table::PokerTable, FE};
use std::collections::HashMap;

pub struct Casino {
    tables: HashMap<FE, PokerTable>,
}

impl Casino {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    /// Add new poker table
    pub fn add_table(&mut self, table: PokerTable) -> FE {
        let table_id = table.table_id.clone();
        self.tables.insert(table.table_id, table);

        table_id
    }
    pub fn get_table(&self, table_id: &FE) -> Option<&PokerTable> {
        self.tables.get(table_id)
    }
}
