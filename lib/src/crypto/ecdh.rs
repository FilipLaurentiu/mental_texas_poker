use crate::{CurvePoint, FE};
use lambdaworks_math::cyclic_group::IsGroup;

/// Compute Diffie-Hellman secret key from the secret key and the other player public key.
pub fn ecdh_secret(secret_key: &FE, player_pub_key: &CurvePoint) -> FE {
    let secret = player_pub_key.operate_with_self(secret_key.representative());
    *secret.to_affine().x()
}

#[cfg(test)]
mod tests {
    use crate::crypto::ecdh::ecdh_secret;
    use crate::utils::get_random_fe_scalar;
    use lambdaworks_math::cyclic_group::IsGroup;
    use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
    use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;

    #[test]
    fn test_ecdh_secret() {
        let g = StarkCurve::generator();
        let private_key1 = get_random_fe_scalar();
        let pub_key1 = g.operate_with_self(private_key1.representative());

        let private_key2 = get_random_fe_scalar();
        let pub_key2 = g.operate_with_self(private_key2.representative());

        assert_eq!(
            ecdh_secret(&private_key1, &pub_key2),
            ecdh_secret(&private_key2, &pub_key1)
        );
    }
}
