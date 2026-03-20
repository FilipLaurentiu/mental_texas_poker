use crate::{
    utils::{cairo_short_string_to_fe, hash_to_stark_curve}, CurvePoint,
    Fe,
};
use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::traits::IsEllipticCurve,
};
use rand::seq::SliceRandom;
use std::{
    collections::HashMap,
    ops::{Index, Mul, Neg},
};

pub struct CardTable {
    enc_cards: Vec<CurvePoint>,
    affine_to_card: HashMap<(Fe, Fe), u8>,
}

impl CardTable {
    pub fn new() -> Self {
        let domain_separator = cairo_short_string_to_fe("BlackBox").unwrap();

        let mut affine_to_card: HashMap<(Fe, Fe), u8> = HashMap::new();

        let mut enc_cards: Vec<CurvePoint> = vec![];

        for i in 0..52u8 {
            let card_number_felt = cairo_short_string_to_fe(&format!("{}", i)).unwrap();
            let card = PedersenStarkCurve::hash(&domain_separator, &card_number_felt);

            let encoded_card = Self::encode_card(card);

            enc_cards.push(encoded_card.clone());

            affine_to_card.insert((*encoded_card.x(), *encoded_card.y()), i);
        }

        Self {
            enc_cards,
            affine_to_card,
        }
    }

    pub fn encode_card(card: Fe) -> CurvePoint {
        hash_to_stark_curve(card)
    }

    pub fn get_card_number(&self, encoded_card: CurvePoint) -> Option<&u8> {
        self.affine_to_card
            .get(&(*encoded_card.x(), *encoded_card.y()))
    }

    /// Pedersen hash of the deck.
    fn hash(&self) -> Fe {
        self.enc_cards
            .iter()
            .fold(Fe::zero(), |current_hash, enc_card| {
                PedersenStarkCurve::hash(
                    &current_hash,
                    &PedersenStarkCurve::hash(&enc_card.x(), &enc_card.y()),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::utils::new_ec_from_x;
    use crate::{assets::deck::CardTable, CurvePoint, Fe};
    use std::ops::Index;

    #[test]
    fn test_map_deck_to_curve() {
        let encoded_deck = CardTable::new();

        for (i, point) in encoded_deck.enc_cards.iter().enumerate() {
            let index = encoded_deck
                .affine_to_card
                .get(&(*point.x(), *point.y()))
                .unwrap();

            assert_eq!(i as u8, *index, "Invalid index");
        }
    }

    #[test]
    fn test_card_to_curve_point() {
        let encoded_deck = CardTable::new();
        let card_position = 11;
        let card: CurvePoint = encoded_deck.enc_cards.index(card_position).clone();
        let card_number = encoded_deck.get_card_number(card).unwrap();

        assert_eq!(*card_number, card_position as u8);
    }

    #[test]
    fn test_recover_x() {
        for i in 1..52 {
            assert!(new_ec_from_x(&Fe::from(i)).is_some());
        }
    }
}
