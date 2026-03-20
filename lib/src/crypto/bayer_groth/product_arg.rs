//! §4  Product Argument
//!
//! Proves:  given commitments cs[0..n-1] to scalars a[0..n-1],
//!          the product  ∏ a[i] = b  (mod q).
//!
//! Strategy — running-product chain
//! ──────────────────────────────────
//! Define   bk[0] = 1
//!          bk[k] = bk[k-1] · a[k-1]
//!          bk[n] = b = ∏ a[i]
//!
//! Commit to intermediate products with fresh randomness t[k]:
//!   d[0]   = com(1 ; 0)   = H          ← public (verifier can compute)
//!   d[k]   = com(bk[k]; t[k-1])        k = 1..n-1
//!   d[n]   = com(b ; 0)   = b·H        ← public
//!
//! For each step k = 0..n-1, prove via MulArg:
//!   A = d[k]    opens to bk[k]    with randomness dr[k]
//!   B = cs[k]   opens to a[k]     with randomness  r[k]
//!   C = d[k+1]  opens to bk[k+1] with randomness dr[k+1]
//!
//! The verifier only needs d[1..n-1] plus the n mul-proofs.

use crate::crypto::bayer_groth::commitment::{commit, h_generator};
use crate::crypto::bayer_groth::mul_arg::{mul_prove, mul_verify, MulProof};
use crate::utils::get_random_fe_scalar;
use crate::{CurvePoint, FeScalar};
use lambdaworks_math::cyclic_group::IsGroup;
use rand_core::{CryptoRng, RngCore};
// ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ProductProof {
    /// Intermediate commitments d[1] … d[n-1].
    pub d_inner: Vec<CurvePoint>,
    /// One MulProof per step.
    pub mul_proofs: Vec<MulProof>,
}

/// Prove that the committed values multiply to `b`.
///
/// `cs`     : commitments  com(a[i]; r[i])
/// `a_vals` : plaintext values
/// `r_vals` : randomness
/// `b`      : claimed product
pub fn product_prove<R: RngCore + CryptoRng>(
    cs: &[CurvePoint],
    a_vals: &[FeScalar],
    r_vals: &[FeScalar],
    b: &FeScalar,
) -> ProductProof {
    let n = cs.len();
    assert_eq!(n, a_vals.len());
    assert_eq!(n, r_vals.len());

    // Running products: bk[0]=1, bk[k] = ∏_{i<k} a[i]
    let mut bk = vec![FeScalar::zero(); n + 1];
    bk[0] = FeScalar::one();
    for i in 0..n {
        bk[i + 1] = bk[i] * a_vals[i];
    }
    debug_assert_eq!(bk[n], *b, "product_prove: claimed product mismatch");

    // Fresh randomness for intermediate commitments
    // d[0] uses r=0 → com = H; d[n] uses r=0 → com = b·H
    let mut t = vec![FeScalar::zero(); n + 1];
    for i in 1..n {
        t[i] = get_random_fe_scalar();
    }

    // d[k] = com(bk[k]; t[k])
    let h = h_generator();
    let mut d: Vec<CurvePoint> = (0..=n)
        .map(|k| {
            if k == 0 {
                h // com(1; 0) = 0·G + 1·H = H
            } else if k == n {
                h.operate_with_self(b.representative()) // com(b; 0) = 0·G + b·H
            } else {
                commit(&bk[k], &t[k])
            }
        })
        .collect();

    // One multiplication proof per step
    let mul_proofs: Vec<MulProof> = (0..n)
        .map(|k| {
            mul_prove(
                &d[k],      // A = d[k]
                &cs[k],     // B = cs[k]
                &d[k + 1],  // C = d[k+1]
                &bk[k],     // a = bk[k]
                &t[k],      // r_a
                &a_vals[k], // b (the multiplier)
                &r_vals[k], // r_b
                &t[k + 1],  // r_c  (= dr[k+1])
            )
        })
        .collect();

    ProductProof {
        d_inner: d[1..n].to_vec(),
        mul_proofs,
    }
}

/// Verify the product argument.
pub fn product_verify(cs: &[CurvePoint], b: &FeScalar, pf: &ProductProof) -> bool {
    let n = cs.len();
    if pf.d_inner.len() != n.saturating_sub(1) {
        return false;
    }
    if pf.mul_proofs.len() != n {
        return false;
    }

    let h = h_generator();

    // Reconstruct full d chain: d[0]=H, d[1..n-1]=d_inner, d[n]=b·H
    let mut d: Vec<CurvePoint> = Vec::with_capacity(n + 1);
    d.push(h.clone());
    d.extend_from_slice(&pf.d_inner);
    d.push(h.operate_with_self(b.representative()));

    // Check each multiplication proof
    (0..n).all(|k| mul_verify(&d[k], &cs[k], &d[k + 1], &pf.mul_proofs[k]))
}

// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn run_product_test(n: usize) {
        let a_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
        let r_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
        let cs: Vec<CurvePoint> = a_vals
            .iter()
            .zip(&r_vals)
            .map(|(a, r)| commit(a, r))
            .collect();

        let b = a_vals.iter().fold(FeScalar::one(), |acc, a| acc * a);
        let pf = product_prove(&cs, &a_vals, &r_vals, &b);
        assert!(product_verify(&cs, &b, &pf), "n={n} failed");
    }

    #[test]
    fn product_n1() {
        run_product_test(1);
    }
    #[test]
    fn product_n4() {
        run_product_test(4);
    }
    #[test]
    fn product_n8() {
        run_product_test(8);
    }

    #[test]
    fn product_wrong_b_rejected() {
        let n = 4;
        let a_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
        let r_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
        let cs = a_vals
            .iter()
            .zip(&r_vals)
            .map(|(a, r)| commit(a, r))
            .collect::<Vec<_>>();
        let b = a_vals.iter().fold(FeScalar::one(), |acc, a| acc * a);
        let pf = product_prove(&cs, &a_vals, &r_vals, &b);
        let wrong_b = b + FeScalar::one();
        assert!(!product_verify(&cs, &wrong_b, &pf));
    }
}
