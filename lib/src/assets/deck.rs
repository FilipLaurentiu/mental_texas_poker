use crate::utils::hash_to_stark_curve;
use rand::seq::SliceRandom;
use starknet::core::utils::cairo_short_string_to_felt;
use starknet_crypto::poseidon_hash;
use starknet_types_core::{
    curve::AffinePoint,
    felt::Felt,
    hash::{Pedersen, StarkHash},
};
use std::ops::Neg;
use std::{
    collections::HashMap,
    ops::{Index, Mul},
};

struct EncodedDeck {
    enc_cards: Vec<AffinePoint>,
    affine_to_card: HashMap<(Felt, Felt), u8>,
}

impl EncodedDeck {
    fn new() -> Self {
        let domain_separator = cairo_short_string_to_felt("BlackBox").unwrap();

        let mut affine_to_card: HashMap<(Felt, Felt), u8> = HashMap::new();

        let mut enc_cards: Vec<AffinePoint> = vec![];

        for i in 0..52u8 {
            let card_number_felt = Felt::from_dec_str(&format!("{}", i)).unwrap();
            let card = poseidon_hash(domain_separator, card_number_felt);

            let encrypted_card = hash_to_stark_curve(card, None);

            enc_cards.push(encrypted_card.clone());

            affine_to_card.insert((encrypted_card.x(), encrypted_card.y()), i);
        }

        Self {
            enc_cards,
            affine_to_card,
        }
    }

    fn get_card_number(&self, encoded_card: AffinePoint) -> Option<&u8> {
        self.affine_to_card
            .get(&(encoded_card.x(), encoded_card.y()))
    }

    /// Pedersen hash of the deck.
    fn hash(&self) -> Felt {
        self.enc_cards
            .iter()
            .fold(Felt::ZERO, |current_hash, enc_card| {
                Pedersen::hash(&current_hash, &Pedersen::hash(&enc_card.x(), &enc_card.y()))
            })
    }
}
struct EncryptedDeck {
    c1: AffinePoint,
    encrypted_cards: Vec<AffinePoint>,
}

impl EncryptedDeck {
    fn new(encoded_deck: &EncodedDeck, r: Felt, pub_shared_key: &AffinePoint) -> Self {
        let c1 = AffinePoint::generator().mul(r);

        let mut encrypted_cards = vec![];

        for enc_card in encoded_deck.enc_cards.clone() {
            encrypted_cards.push(enc_card + pub_shared_key * r);
        }

        let mut rng = rand::rng();
        encrypted_cards.shuffle(&mut rng);

        Self {
            c1,
            encrypted_cards,
        }
    }

    fn encrypt_and_shuffle(mut encrypted_deck: EncryptedDeck, r: Felt) -> EncryptedDeck {
        let c1 = AffinePoint::generator().mul(r);

        let mut rng = rand::rng();
        encrypted_deck.encrypted_cards.shuffle(&mut rng);

        let encrypted_cards: Vec<AffinePoint> = encrypted_deck
            .encrypted_cards
            .iter_mut()
            .map(|encrypted_card| encrypted_card.clone() + c1.clone())
            .collect();

        Self {
            c1: c1 + encrypted_deck.c1,
            encrypted_cards,
        }
    }

    /// Decrypt card.
    ///
    /// Remove last layer of decryption and get your card.
    /// Other users should already have removed their encryption layer.
    fn decrypt_card(
        c1: &AffinePoint,
        encrypted_card: AffinePoint,
        s: Felt,
        encoded_deck: &EncodedDeck,
    ) -> Option<u8> {
        let s_c1 = c1 * s;

        let encoded_card = encrypted_card + s_c1.neg();
        if let Some(card) = encoded_deck.get_card_number(encoded_card) {
            return Some(*card);
        }
        None
    }

    /// Partial decryption of the card.
    ///
    /// Remove your encryption layer for other users to see their cards.
    fn decrypt_partial(c1: &AffinePoint, encrypted_card: AffinePoint, s: Felt) -> AffinePoint {
        let c1_s = c1 * s;

        let partial_decrypted_card: AffinePoint = encrypted_card + c1_s.neg();
        partial_decrypted_card
    }
}

#[cfg(test)]
mod tests {
    use crate::assets::deck::EncodedDeck;
    use starknet_types_core::curve::AffinePoint;
    use std::ops::Index;

    #[test]
    fn test_map_deck_to_curve() {
        let encoded_deck = EncodedDeck::new();

        for (i, point) in encoded_deck.enc_cards.iter().enumerate() {
            let index = encoded_deck
                .affine_to_card
                .get(&(point.x(), point.y()))
                .unwrap();

            assert_eq!(i as u8, *index, "Invalid index");
        }
    }

    #[test]
    fn test_card_to_curve_point() {
        let encoded_deck = EncodedDeck::new();
        let card_position = 11;
        let card: AffinePoint = encoded_deck.enc_cards.index(card_position).clone();
        let card_number = encoded_deck.get_card_number(card).unwrap();

        assert_eq!(*card_number, card_position as u8);
    }
}
