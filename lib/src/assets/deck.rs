use crate::utils::hash_to_stark_curve;
use starknet::core::utils::cairo_short_string_to_felt;
use starknet_crypto::poseidon_hash;
use starknet_types_core::{
    curve::AffinePoint,
    felt::Felt,
    hash::{Pedersen, StarkHash},
};
use std::collections::HashMap;
use std::ops::Index;

struct EncodedCards {
    enc_cards: Vec<AffinePoint>,
}

impl EncodedCards {
    fn get_card_number(encoded_card: AffinePoint) -> Option<u8> {
        let (_, cards_map) = map_deck_to_curve();

        if let Some(card_index) = cards_map.get(&(encoded_card.x(), encoded_card.y())) {
            return Some(*card_index);
        }

        None
    }
}

struct Deck {
    cards: Vec<AffinePoint>,
}

impl Deck {
    /// Pedersen hash of the deck.
    fn hash(&self) -> Felt {
        self.cards
            .iter()
            .fold(Felt::ZERO, |current_hash, enc_card| {
                Pedersen::hash(&current_hash, &Pedersen::hash(&enc_card.x(), &enc_card.y()))
            })
    }

    fn shuffle_and_encrypt(private_key: Felt) -> (AffinePoint, Vec<AffinePoint>) {
        unimplemented!()
    }
}

struct EncryptedDeck {
    c1: AffinePoint,
    enc_cards: Vec<AffinePoint>,
}

pub fn map_deck_to_curve() -> (Vec<AffinePoint>, HashMap<(Felt, Felt), u8>) {
    let domain_separator = cairo_short_string_to_felt("BlackBox").unwrap();

    let mut encrypted_deck_map: HashMap<(Felt, Felt), u8> = HashMap::new();

    let mut encrypted_deck: Vec<AffinePoint> = vec![];

    for i in 0..52u8 {
        let card_number_felt = Felt::from_dec_str(&format!("{}", i)).unwrap();
        let card = poseidon_hash(domain_separator, card_number_felt);

        let encrypted_card = hash_to_stark_curve(card, None);

        encrypted_deck.push(encrypted_card.clone());

        encrypted_deck_map.insert((encrypted_card.x(), encrypted_card.y()), i);
    }

    (encrypted_deck, encrypted_deck_map)
}

#[cfg(test)]
mod tests {
    use crate::assets::deck::map_deck_to_curve;

    #[test]
    fn test_map_deck_to_curve() {
        let (enc_vec, enc_map) = map_deck_to_curve();

        for (i, point) in enc_vec.iter().enumerate() {
            let index = enc_map.get(&(point.x(), point.y())).unwrap();

            assert_eq!(i as u8, *index, "Invalid index");
        }
    }
}
