use starknet_crypto::get_public_key;
use starknet_types_core::curve::AffinePoint;
use starknet_types_core::felt::{Felt, secret_felt::SecretFelt};

pub struct Player {
    wallet: Felt,
    secret_key: SecretFelt,
    enc_cards: [AffinePoint; 2]
}

impl Player {
    pub fn pub_key(&self) -> Felt {
        get_public_key(&self.secret_key.inner_value())
    }
}
