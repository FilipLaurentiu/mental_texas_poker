use crate::{
    constants::CURVE_ORDER_FE, utils::{add_mod, get_random_fe_scalar, inv_mod, mul_mod},
    CurvePoint,
    FE,
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{
        short_weierstrass::{curves::stark_curve::StarkCurve, traits::IsShortWeierstrass},
        traits::IsEllipticCurve,
    },
    traits::ByteConversion,
};

/// From https://github.com/lambdaclass/lambdaworks/blob/ca9241e29bcacd253fe011aa3494853fe6f799f1/examples/ecdsa-signature/src/ecdsa.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature {
    /// The x-coordinate of the random point R = k*G (mod n)
    pub r: FE,
    /// The signature proof s = k^(-1) * (z + r*d) (mod n)
    pub s: FE,
}

/// Errors that can occur during ECDSA operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaError {
    /// The signature r component is zero or out of range
    InvalidRValue,
    /// The signature s component is zero or out of range
    InvalidSValue,
    /// The nonce k is invalid (zero or >= order)
    InvalidNonce,
    /// Failed to compute the inverse
    InverseError,
    /// The message hash is invalid
    InvalidMessageHash,
    /// Signature verification failed
    VerificationFailed,
    /// Public key is not a valid curve point
    InvalidPublicKey,
}

/// Check if a point is on the StarkCurve curve.
/// Verifies that y² = x³ + a*x + b (mod p).
fn is_point_on_curve(point: &CurvePoint) -> bool {
    // Point at infinity is technically on the curve
    if *point == CurvePoint::neutral_element() {
        return true;
    }

    let affine = point.to_affine();
    let x = affine.x();
    let y = affine.y();

    // Check curve equation: y² = x³ + a*x + b (where b = 0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89 and a = 1)
    let y_sq = y * y;
    let x_cubed = x * x * x;
    let rhs = x_cubed + x + StarkCurve::b();

    y_sq == rhs
}

impl EcdsaSignature {
    /// Create a new signature from r and s values.
    ///
    /// Returns an error if r or s is zero.
    pub fn new(r: &FE, s: &FE) -> Result<Self, EcdsaError> {
        if *r == FE::zero() {
            return Err(EcdsaError::InvalidRValue);
        }
        if *s == FE::zero() {
            return Err(EcdsaError::InvalidSValue);
        }
        Ok(Self { r: *r, s: *s })
    }

    /// Serialize the signature to bytes (64 bytes: 32 for r, 32 for s).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let r_bytes = self.r.to_bytes_be();
        let s_bytes = self.s.to_bytes_be();

        bytes[..32].copy_from_slice(&r_bytes);
        bytes[32..].copy_from_slice(&s_bytes);
        bytes
    }

    /// Deserialize a signature from bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, EcdsaError> {
        let r = FE::from_bytes_be(&bytes[..32]).map_err(|_| EcdsaError::InvalidRValue)?;
        let s = FE::from_bytes_be(&bytes[32..]).map_err(|_| EcdsaError::InvalidSValue)?;
        Self::new(&r, &s)
    }

    /// Sign a message hash using ECDSA.
    ///
    /// # Arguments
    /// * `message_hash` - The 32-byte hash of the message to sign
    /// * `private_key` - The private key (scalar)
    /// * `nonce` - The random nonce k (MUST be cryptographically random and unique per signature)
    ///
    /// # Security Warning
    /// This implementation is NOT constant-time. For production use, ensure:
    /// 1. The nonce is generated using a CSPRNG
    /// 2. Each nonce is used only once
    /// 3. Use RFC 6979 for deterministic nonce generation
    ///
    /// # Returns
    /// A signature (r, s) or an error if the inputs are invalid.
    pub fn sign(
        message_hash: &[u8; 32],
        private_key: &FE,
        nonce: Option<&FE>,
    ) -> Result<Self, EcdsaError> {
        // Validate nonce is not zero
        let nonce = if nonce.is_some() {
            nonce.unwrap()
        } else {
            &get_random_fe_scalar()
        };

        if *nonce == FE::zero() {
            return Err(EcdsaError::InvalidNonce);
        }

        // R = k * G
        let generator = StarkCurve::generator();
        let r_point = generator.operate_with_self(nonce.representative());
        let r_affine = r_point.to_affine();

        // r = R.x mod n
        // Convert x coordinate from base field to scalar field
        let r_x_bytes = r_affine.x().to_bytes_be();
        let r = FE::from_bytes_be(&r_x_bytes).map_err(|_| EcdsaError::InvalidRValue)?;

        if r == FE::zero() {
            return Err(EcdsaError::InvalidRValue);
        }

        // z = message_hash as scalar field element
        let z = FE::from_bytes_be(message_hash).map_err(|_| EcdsaError::InvalidMessageHash)?;

        let k_inv = inv_mod(nonce, &CURVE_ORDER_FE).ok_or_else(|| EcdsaError::InverseError)?;

        // s = k^(-1) * (z + r * d) mod n
        let rd = mul_mod(&r, &private_key, &CURVE_ORDER_FE);
        let temp = add_mod(&z, &rd, &CURVE_ORDER_FE);
        let mut s = mul_mod(&k_inv, &temp, &CURVE_ORDER_FE);

        if s == FE::zero() {
            return Err(EcdsaError::InvalidSValue);
        }

        // Normalize to low-S form to prevent signature malleability.
        if *s.to_bits_le().first().unwrap() == false {
            s = &CURVE_ORDER_FE - s;
        }

        Self::new(&r, &s)
    }

    pub fn verify(
        &self,
        message_hash: &[u8; 32],
        public_key: &CurvePoint,
    ) -> Result<(), EcdsaError> {
        // Validate r and s are non-zero (they're already reduced mod n by FieldElement)
        if self.r == FE::zero() {
            return Err(EcdsaError::InvalidRValue);
        }
        if self.s == FE::zero() {
            return Err(EcdsaError::InvalidSValue);
        }

        // Reject high-S signatures to prevent malleability
        if *self.s.to_bits_le().first().unwrap() == false {
            return Err(EcdsaError::InvalidSValue);
        }

        // Validate public key is on the curve
        if !is_point_on_curve(public_key) {
            return Err(EcdsaError::InvalidPublicKey);
        }

        // Reject point at infinity as public key
        if *public_key == CurvePoint::neutral_element() {
            return Err(EcdsaError::InvalidPublicKey);
        }

        // z = message_hash as scalar field element
        let z = FE::from_bytes_be(message_hash).map_err(|_| EcdsaError::InvalidMessageHash)?;

        // s_inv = s^(-1) mod n
        let s_inv = inv_mod(&self.s, &CURVE_ORDER_FE).ok_or_else(|| EcdsaError::InverseError)?;

        // u1 = z * s^(-1) mod n
        let u1 = mul_mod(&z, &s_inv, &CURVE_ORDER_FE);

        // u2 = r * s^(-1) mod n
        let u2 = mul_mod(&self.r, &s_inv, &CURVE_ORDER_FE);

        // R' = u1 * G + u2 * Q
        let generator = StarkCurve::generator();
        let u1_g = generator.operate_with_self(u1.representative());
        let u2_q = public_key.operate_with_self(u2.representative());
        let r_prime = u1_g.operate_with(&u2_q);

        // Check if R' is the point at infinity
        if r_prime == CurvePoint::neutral_element() {
            return Err(EcdsaError::VerificationFailed);
        }

        let r_prime_affine = r_prime.to_affine();

        // r' = R'.x mod n
        let r_prime_x_bytes = r_prime_affine.x().to_bytes_be();
        let r_prime_scalar =
            FE::from_bytes_be(&r_prime_x_bytes).map_err(|_| EcdsaError::VerificationFailed)?;

        // Verify r == r'
        if self.r == r_prime_scalar {
            Ok(())
        } else {
            Err(EcdsaError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{crypto::ecdsa::EcdsaSignature, utils::get_random_fe_scalar, FE};
    use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve,
        },
    };

    #[test]
    fn test_ecdsa() {
        let private_key = get_random_fe_scalar();
        let public_key = StarkCurve::generator().operate_with_self(private_key.representative());
        let nonce = get_random_fe_scalar();

        /// message
        let message = PedersenStarkCurve::hash(&FE::from(20), &FE::from(30));

        let signature =
            EcdsaSignature::sign(&message.to_bytes_be(), &private_key, Some(&nonce)).unwrap();

        assert!(
            signature
                .verify(&message.to_bytes_be(), &public_key)
                .is_ok()
        );
    }
}
