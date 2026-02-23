use crate::{crypto::utils::new_ec_from_x, FE};
use lambdaworks_math::cyclic_group::IsGroup;

#[derive(Debug)]
pub enum EcdhSecretError {
    InvalidCurvePoint,
}

/// Compute Diffie-Hellman secret key from the secret key and the other player public key.
/// - `sk` - Secret key
/// - `pk_x` - Public key x coordinate
pub fn ecdh_secret(sk: &FE, pk_x: &FE) -> Result<FE, EcdhSecretError> {
    let player_pub_key = new_ec_from_x(pk_x).ok_or(EcdhSecretError::InvalidCurvePoint)?;
    let secret = player_pub_key.operate_with_self(sk.representative());
    Ok(*secret.to_affine().x())
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
            ecdh_secret(&private_key1, &pub_key2.to_affine().x()).unwrap(),
            ecdh_secret(&private_key2, &pub_key1.to_affine().x()).unwrap()
        );
    }
}
