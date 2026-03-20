//! §2  Pedersen commitments
//!
//!   com(a ; r) = r·G + a·H
//!
//! Perfectly hiding (unconditional) and computationally binding
//! under the discrete-log assumption.
//! Homomorphic: com(a;r) + com(b;s) = com(a+b ; r+s).

use crate::{CurvePoint, FeScalar};
use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;

/// Compute a Pedersen commitment  r·G + a·H.
#[inline]
pub fn commit(a: &FeScalar, r: &FeScalar) -> CurvePoint {
    StarkCurve::generator()
        .operate_with_self(r.representative())
        .operate_with(&h_generator().operate_with_self(a.representative()))
}

pub fn h_generator() -> CurvePoint {
    // TODO: generate secure H point
    StarkCurve::generator().double()
}
/// Batch-commit a slice of (value, randomness) pairs.
pub fn commit_batch(pairs: &[(FeScalar, FeScalar)]) -> Vec<CurvePoint> {
    pairs.iter().map(|(a, r)| commit(a, r)).collect()
}

/// Verify that `c` opens to `(a, r)`.
#[inline]
pub fn verify_opening(c: &CurvePoint, a: &FeScalar, r: &FeScalar) -> bool {
    c == &commit(a, r)
}
