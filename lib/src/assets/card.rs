use crate::CurvePoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suit {
    Clubs,
    Diamonds,
    Hearts,
    Spades,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rank {
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
    Ten,
    Jack,
    Queen,
    King,
    Ace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Card {
    rank: Rank,
    suit: Suit,
}

impl Card {
    pub fn from_index(n: u8) -> Option<Card> {
        if n >= 52 {
            return None;
        }

        let suit = match n / 13 {
            0 => Suit::Clubs,
            1 => Suit::Diamonds,
            2 => Suit::Hearts,
            3 => Suit::Spades,
            _ => unreachable!(),
        };

        let rank = match n % 13 {
            0 => Rank::Two,
            1 => Rank::Three,
            2 => Rank::Four,
            3 => Rank::Five,
            4 => Rank::Six,
            5 => Rank::Seven,
            6 => Rank::Eight,
            7 => Rank::Nine,
            8 => Rank::Ten,
            9 => Rank::Jack,
            10 => Rank::Queen,
            11 => Rank::King,
            12 => Rank::Ace,
            _ => unreachable!(),
        };

        Some(Card { rank, suit })
    }
}

impl std::fmt::Display for Card {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rank = match self.rank {
            Rank::Two => "2",
            Rank::Three => "3",
            Rank::Four => "4",
            Rank::Five => "5",
            Rank::Six => "6",
            Rank::Seven => "7",
            Rank::Eight => "8",
            Rank::Nine => "9",
            Rank::Ten => "10",
            Rank::Jack => "Jack",
            Rank::Queen => "Queen",
            Rank::King => "King",
            Rank::Ace => "Ace",
        };

        let suit = match self.suit {
            Suit::Clubs => "Clubs",
            Suit::Diamonds => "Diamonds",
            Suit::Hearts => "Hearts",
            Suit::Spades => "Spades",
        };

        write!(f, "{} of {}", rank, suit)
    }
}


pub struct EncryptedCard {
    pub c1: CurvePoint,
    pub c2: CurvePoint,
}

#[cfg(test)]
mod tests {
    use crate::assets::card::{Card, Rank, Suit};

    #[test]
    fn test_card_from_index() {
        for i in 0..52u8 {
            assert!(Card::from_index(i).is_some());
        }

        let ace_spades = Card::from_index(51).unwrap();
        assert_eq!(ace_spades.rank, Rank::Ace);
        assert_eq!(ace_spades.suit, Suit::Spades);

        let two = Card::from_index(0).unwrap();
        assert_eq!(two.rank, Rank::Two);
        assert_eq!(two.suit, Suit::Clubs);
    }
}
