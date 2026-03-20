//! §3  Multiplication Argument
//!
//! Proves: given commitments A = com(a;rₐ), B = com(b;r_b), C = com(a·b;r_c),
//! the prover knows a, rₐ such that the product relation holds.
//!
//! Key identity
//! ────────────
//!   a·B − C  =  (a·r_b − r_c)·G          [let δ = a·r_b − r_c]
//!
//! So it suffices to prove knowledge of (a, rₐ, δ) satisfying:
//!   A = rₐ·G + a·H       (standard Pedersen opening)
//!   a·B − C = δ·G        (product relation encoded as DL)
//!
//! Σ-protocol (Fiat-Shamir collapsed)
//! ───────────────────────────────────
//! Commit:   k, r_k, d  ←$  Zq
//!           R = r_k·G + k·H
//!           S = k·B − d·G
//!
//! Challenge: e = H(A, B, C, R, S)   [recomputed by verifier]
//!
//! Respond:  f   = k + e·a   mod q
//!           z_r = r_k + e·rₐ mod q
//!           z_d = d + e·δ   mod q
//!
//! Verify:
//!   (i)   z_r·G + f·H  = R + e·A
//!   (ii)  f·B − z_d·G  = S + e·C

use crate::crypto::bayer_groth::commitment::h_generator;
use crate::crypto::bayer_groth::transcript::Transcript;
use crate::utils::get_random_fe_scalar;
use crate::{CurvePoint, FeScalar};
use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;
use rand_core::{CryptoRng, RngCore};
// ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MulProof {
    pub r_pt: CurvePoint, // R
    pub s_pt: CurvePoint, // S
    pub f: FeScalar,
    pub z_r: FeScalar,
    pub z_d: FeScalar,
}

/// Produce a multiplication proof.
///
/// Inputs:
///   cap_a, cap_b, cap_c  — commitments (public)
///   a, r_a               — opening of A
///   b, r_b               — opening of B
///   r_c                  — randomness of C  (a·b is implicit)
pub fn mul_prove(
    cap_a: &CurvePoint,
    cap_b: &CurvePoint,
    cap_c: &CurvePoint,
    a: &FeScalar,
    r_a: &FeScalar,
    _b: &FeScalar,
    r_b: &FeScalar,
    r_c: &FeScalar,
) -> MulProof {
    let g = StarkCurve::generator();
    let h = h_generator();

    // δ = a·r_b − r_c
    let delta = a * r_b - r_c;

    // Commit phase
    let k = get_random_fe_scalar();
    let r_k = get_random_fe_scalar();
    let d = get_random_fe_scalar();

    // R = r_k·G + k·H
    let r_pt = g
        .operate_with_self(&r_k.representative())
        .operate_with(&h.operate_with_self(&k.representative()));
    // S = k·B − d·G
    let s_pt = cap_b
        .operate_with_self(&k.representative())
        .operate_with(&g.operate_with_self(&d.representative()).neg());

    // Challenge (Fiat-Shamir)
    let e = {
        let mut ts = Transcript::new(b"mul-arg");
        ts.append_point(cap_a);
        ts.append_point(cap_b);
        ts.append_point(cap_c);
        ts.append_point(&r_pt);
        ts.append_point(&s_pt);
        ts.challenge()
    };

    MulProof {
        r_pt,
        s_pt,
        f: k + e * a,
        z_r: r_k + e * r_a,
        z_d: d + e * delta,
    }
}

/// Verify a multiplication proof.
/// The challenge is always recomputed from the transcript.
pub fn mul_verify(
    cap_a: &CurvePoint,
    cap_b: &CurvePoint,
    cap_c: &CurvePoint,
    pf: &MulProof,
) -> bool {
    let g = StarkCurve::generator();
    let h = h_generator();

    let e = {
        let mut ts = Transcript::new(b"mul-arg");
        ts.append_point(cap_a);
        ts.append_point(cap_b);
        ts.append_point(cap_c);
        ts.append_point(&pf.r_pt);
        ts.append_point(&pf.s_pt);
        ts.challenge()
    };

    // (i)  z_r·G + f·H  = R + e·A
    let lhs1 = g
        .operate_with_self(&pf.z_r.representative())
        .operate_with(&h.operate_with_self(&pf.f.representative()));
    let rhs1 = pf
        .r_pt
        .operate_with(&cap_a.operate_with_self(&e.representative()));

    // (ii) f·B − z_d·G  = S + e·C
    let lhs2 = cap_b
        .operate_with_self(&pf.f.representative())
        .operate_with(&g.operate_with_self(&pf.z_d.representative()).neg());
    let rhs2 = pf
        .s_pt
        .operate_with(&cap_c.operate_with_self(&e.representative()));

    lhs1 == rhs1 && lhs2 == rhs2
}

// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::bayer_groth::commitment::commit;

    #[test]
    fn mul_proof_roundtrip() {
        let a = get_random_fe_scalar();
        let b = get_random_fe_scalar();
        let c = a * b;
        let ra = get_random_fe_scalar();
        let rb = get_random_fe_scalar();
        let rc = get_random_fe_scalar();

        let cap_a = commit(&a, &ra);
        let cap_b = commit(&b, &rb);
        let cap_c = commit(&c, &rc);

        let pf = mul_prove(&cap_a, &cap_b, &cap_c, &a, &ra, &b, &rb, &rc);
        assert!(mul_verify(&cap_a, &cap_b, &cap_c, &pf));
    }

    #[test]
    fn mul_proof_wrong_product_rejected() {
        let a = get_random_fe_scalar();
        let b = get_random_fe_scalar();
        let c = a * b + FeScalar::one(); // wrong!
        let ra = get_random_fe_scalar();
        let rb = get_random_fe_scalar();
        let rc = get_random_fe_scalar();

        let cap_a = commit(&a, &ra);
        let cap_b = commit(&b, &rb);
        let cap_c = commit(&c, &rc); // commits to wrong value

        // Prover passes wrong r_c — proof will be inconsistent
        let pf = mul_prove(&cap_a, &cap_b, &cap_c, &a, &ra, &b, &rb, &rc);
        assert!(!mul_verify(&cap_a, &cap_b, &cap_c, &pf));
    }
}
