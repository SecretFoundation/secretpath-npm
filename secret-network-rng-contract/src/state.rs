use cosmwasm_std::{Addr, Binary};
use secret_toolkit::storage::{Item, Keymap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub static CONFIG: Item<State> = Item::new(b"config");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub gateway_address: Addr,
    pub gateway_hash: String,
    pub gateway_key: Binary,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Input {
    pub random_numbers: String,
    pub wallet_address: String, 
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Random {
    // Number of Words to generate
    pub random: Vec<u16>,
    pub wallet_address: String,
}

pub static STORED_RANDOM: Keymap<bool, Random> = Keymap::new(b"stored_random_numbers");
