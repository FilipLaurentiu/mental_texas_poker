use crate::{
    utils::{cairo_short_string_to_fe, hash_to_stark_curve}, CurvePoint,
    FE,
};
use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
};
use rand::seq::SliceRandom;
use std::{
    collections::HashMap,
    ops::{Index, Mul, Neg},
};

struct EncodedDeck {
    enc_cards: Vec<CurvePoint>,
    affine_to_card: HashMap<(FE, FE), u8>,
}

impl EncodedDeck {
    fn new() -> Self {
        let domain_separator = cairo_short_string_to_fe("BlackBox").unwrap();

        let mut affine_to_card: HashMap<(FE, FE), u8> = HashMap::new();

        let mut enc_cards: Vec<CurvePoint> = vec![];

        for i in 0..52u8 {
            let card_number_felt = cairo_short_string_to_fe(&format!("{}", i)).unwrap();
            let card = PedersenStarkCurve::hash(&domain_separator, &card_number_felt);

            let encrypted_card = hash_to_stark_curve(card);

            enc_cards.push(encrypted_card.clone());

            affine_to_card.insert((*encrypted_card.x(), *encrypted_card.y()), i);
        }

        Self {
            enc_cards,
            affine_to_card,
        }
    }

    fn get_card_number(&self, encoded_card: CurvePoint) -> Option<&u8> {
        self.affine_to_card
            .get(&(*encoded_card.x(), *encoded_card.y()))
    }

    /// Pedersen hash of the deck.
    fn hash(&self) -> FE {
        self.enc_cards
            .iter()
            .fold(FE::zero(), |current_hash, enc_card| {
                PedersenStarkCurve::hash(
                    &current_hash,
                    &PedersenStarkCurve::hash(&enc_card.x(), &enc_card.y()),
                )
            })
    }
}
struct EncryptedDeck {
    c1: CurvePoint,
    encrypted_cards: Vec<CurvePoint>,
}

impl EncryptedDeck {
    fn new(encoded_deck: &EncodedDeck, r: &FE, pub_shared_key: &CurvePoint) -> Self {
        let c1 = StarkCurve::generator().operate_with_self(r.representative());

        let mut encrypted_cards = vec![];

        for enc_card in encoded_deck.enc_cards.clone() {
            encrypted_cards
                .push(enc_card.operate_with(&pub_shared_key.operate_with_self(r.representative())));
        }

        let mut rng = rand::rng();
        encrypted_cards.shuffle(&mut rng);

        Self {
            c1,
            encrypted_cards,
        }
    }

    fn encrypt_and_shuffle(mut encrypted_deck: EncryptedDeck, r: &FE) -> EncryptedDeck {
        let c1 = StarkCurve::generator().operate_with_self(r.representative());

        let mut rng = rand::rng();
        encrypted_deck.encrypted_cards.shuffle(&mut rng);

        let encrypted_cards: Vec<CurvePoint> = encrypted_deck
            .encrypted_cards
            .iter_mut()
            .map(|encrypted_card| encrypted_card.operate_with(&c1))
            .collect();

        Self {
            c1: c1.operate_with(&encrypted_deck.c1),
            encrypted_cards,
        }
    }

    /// Decrypt card.
    ///
    /// Remove last layer of decryption and get your card.
    /// Other users should already have removed their encryption layer.
    fn decrypt_card(
        c1: &CurvePoint,
        encrypted_card: &CurvePoint,
        s: FE,
        encoded_deck: &EncodedDeck,
    ) -> Option<u8> {
        let s_c1 = c1.operate_with_self(s.representative());

        let encoded_card = encrypted_card.operate_with(&s_c1.neg());
        if let Some(card) = encoded_deck.get_card_number(encoded_card) {
            return Some(*card);
        }
        None
    }

    /// Partial decryption of the card.
    ///
    /// Remove your encryption layer for other users to see their cards.
    fn decrypt_partial(c1: &CurvePoint, encrypted_card: &CurvePoint, s: &FE) -> CurvePoint {
        let c1_s = c1.operate_with_self(s.representative());

        let partial_decrypted_card: CurvePoint = encrypted_card.operate_with(&c1_s.neg());
        partial_decrypted_card
    }
}

#[cfg(test)]
mod tests {
    use crate::{assets::deck::EncodedDeck, CurvePoint};
    use std::ops::Index;

    #[test]
    fn test_map_deck_to_curve() {
        let encoded_deck = EncodedDeck::new();

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
        let encoded_deck = EncodedDeck::new();
        let card_position = 11;
        let card: CurvePoint = encoded_deck.enc_cards.index(card_position).clone();
        let card_number = encoded_deck.get_card_number(card).unwrap();

        assert_eq!(*card_number, card_position as u8);
    }
}
