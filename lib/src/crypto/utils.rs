use crate::{CurvePoint, Fe};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{
        short_weierstrass::{curves::stark_curve::StarkCurve, traits::IsShortWeierstrass},
        traits::FromAffine,
        traits::IsEllipticCurve,
    },
};

pub fn new_ec_from_x(x: &Fe) -> Option<CurvePoint> {
    let rhs = x * x * x + x + StarkCurve::b();
    println!("rhs {}", rhs);
    let (root1, _root2) = rhs.sqrt()?;

    Some(CurvePoint::from_affine(*x, root1).unwrap())
}

pub fn ec_array_commitment(elements: &[Fe]) -> Vec<CurvePoint> {
    let g = StarkCurve::generator();
    elements
        .iter()
        .map(|el| g.operate_with_self(el.representative()))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::CURVE_ORDER_FE, crypto::utils::ec_array_commitment, crypto::utils::new_ec_from_x, utils::polynomial_evaluation_mod,
        CurvePoint, Fe,
    };
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve,
        },
    };

    #[test]
    fn test_recover_from_x() {
        let sk = Fe::from(20);
        let pk = StarkCurve::generator().operate_with_self(sk.representative());

        let x = pk.to_affine().x().clone();

        assert_eq!(*new_ec_from_x(&x).unwrap().to_affine().x(), x);
    }

    #[test]
    fn test_ec_array_commitment() {
        let coefficients = vec![Fe::from(10), Fe::from(20), Fe::from(30), Fe::from(40)];
        let commitments = ec_array_commitment(&coefficients);

        let x = Fe::from(5);

        let evaluation = polynomial_evaluation_mod(&x, &coefficients, &CURVE_ORDER_FE);

        let acc = commitments
            .iter()
            .rev()
            .fold(CurvePoint::neutral_element(), |acc, commitment| {
                commitment.operate_with(&acc.operate_with_self(x.representative()))
            });

        assert_eq!(
            acc.to_affine(),
            StarkCurve::generator()
                .operate_with_self(evaluation.representative())
                .to_affine()
        )
    }
}
