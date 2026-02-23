use crate::{CurvePoint, FE};
use lambdaworks_math::elliptic_curve::{
    short_weierstrass::{curves::stark_curve::StarkCurve, traits::IsShortWeierstrass},
    traits::FromAffine,
};

pub fn new_ec_from_x(x: &FE) -> Option<CurvePoint> {
    let rhs = x * x * x + StarkCurve::a() * x + StarkCurve::b();
    let (root1, _root2) = rhs.sqrt()?;

    Some(CurvePoint::from_affine(*x, root1).unwrap())
}

#[cfg(test)]
mod tests {
    use crate::{crypto::utils::new_ec_from_x, FE};
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve,
        },
    };

    #[test]
    fn test_recover_from_x() {
        let sk = FE::from(20);
        let pk = StarkCurve::generator().operate_with_self(sk.representative());

        let x = pk.to_affine().x().clone();

        assert_eq!(*new_ec_from_x(&x).unwrap().to_affine().x(), x);
    }
}
