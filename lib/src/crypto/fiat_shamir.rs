use crate::{CurvePoint, Fe};
use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};

pub fn fiat_shamir_fe(elements: &[Fe]) -> Fe {
    if elements.len() < 2 {
        return PedersenStarkCurve::hash(&Fe::zero(), &elements[0]);
    }

    let mut acc = PedersenStarkCurve::hash(&elements[0], &elements[1]);

    for el in elements.iter().skip(2) {
        acc = PedersenStarkCurve::hash(&acc, &el);
    }

    acc
}

pub fn fiat_shamir_ec(elements: &[CurvePoint]) -> Fe {
    let mut acc = PedersenStarkCurve::hash(&elements[0].x(), &elements[0].y());

    for el in elements.iter().skip(1) {
        acc = PedersenStarkCurve::hash(&acc, &PedersenStarkCurve::hash(&el.x(), el.y()));
    }

    acc
}
