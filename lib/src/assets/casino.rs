use crate::{assets::poker_table::PokerTable, Fe};
use std::collections::HashMap;

pub struct Casino<'a> {
    tables: HashMap<Fe, PokerTable<'a>>,
}

impl Casino<'_> {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    /// Add new poker table
    pub fn add_table(&mut self, table: PokerTable) -> Fe {
        // let table_id = table.table_id.clone();
        // self.tables.insert(table.table_id, table);
        //
        // table_id
        unimplemented!()
    }
    pub fn get_table(&self, table_id: &Fe) -> Option<&PokerTable> {
        self.tables.get(table_id)
    }
}
