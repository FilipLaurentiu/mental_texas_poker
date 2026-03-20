//! §5  Multi-Exponentiation Argument
//!
//! Proves: given commitments cs[i] = com(a[i]; r[i])  and
//!         ElGamal ciphertexts E[i] = (C1[i], C2[i]),
//!
//!   T = Σᵢ a[i]·E[i]  =  (Σ a[i]·C1[i],  Σ a[i]·C2[i])
//!
//! without revealing the scalars a[i].
//!
//! Protocol (batch Schnorr)
//! ──────────────────────────
//! Commit:   b[i], s[i]  ←$  Zq
//!           D[i]  = com(b[i]; s[i])
//!           U     = Σ b[i]·E[i]         (component-wise sum)
//!
//! Challenge: e = H(cs, E, D, T, U)
//!
//! Respond:  f[i] = b[i] + e·a[i]  mod q
//!           z[i] = s[i] + e·r[i]  mod q
//!
//! Verify:
//!   (i)  z[i]·G + f[i]·H = D[i] + e·cs[i]     ∀i
//!   (ii) Σ f[i]·E[i]     = U + e·T              (both components)

use crate::crypto::bayer_groth::commitment::{commit, h_generator};
use crate::crypto::bayer_groth::transcript::Transcript;
use crate::crypto::elgamal::ElGamalCiphertext;
use crate::utils::get_random_fe_scalar;
use crate::{CurvePoint, FeScalar};
use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;
// ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MultiExpProof {
    /// The multi-exp target T = Σ a[i]·E[i].
    pub t1: CurvePoint,
    pub t2: CurvePoint,
    /// Commitments to blinding values.
    pub d_list: Vec<CurvePoint>,
    /// Blinded multi-exp.
    pub u1: CurvePoint,
    pub u2: CurvePoint,
    /// Response scalars.
    pub f_vals: Vec<FeScalar>,
    pub z_vals: Vec<FeScalar>,
}

/// Produce a multi-exponentiation proof.
pub fn multi_exp_prove(
    cs: &[CurvePoint],
    a_vals: &[FeScalar],
    r_vals: &[FeScalar],
    e_list: &[ElGamalCiphertext],
) -> MultiExpProof {
    let n = cs.len();
    assert_eq!(n, a_vals.len());
    assert_eq!(n, r_vals.len());
    assert_eq!(n, e_list.len());

    // Target  T = Σ a[i]·E[i]
    let (t1, t2) = multi_exp_ct(a_vals, e_list);

    // Blinding
    let b_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
    let s_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
    let d_list: Vec<CurvePoint> = b_vals
        .iter()
        .zip(&s_vals)
        .map(|(b, s)| commit(b, s))
        .collect();

    let (u1, u2) = multi_exp_ct(&b_vals, e_list);

    // Challenge
    let e = {
        let mut ts = Transcript::new(b"multi-exp-arg");
        ts.append_points(cs);
        for ct in e_list {
            ts.append_point(&ct.c1);
            ts.append_point(&ct.c2);
        }
        ts.append_points(&d_list);
        ts.append_point(&t1);
        ts.append_point(&t2);
        ts.append_point(&u1);
        ts.append_point(&u2);
        ts.challenge()
    };

    // Responses
    let f_vals: Vec<FeScalar> = b_vals.iter().zip(a_vals).map(|(b, a)| b + e * a).collect();
    let z_vals: Vec<FeScalar> = s_vals.iter().zip(r_vals).map(|(s, r)| s + e * r).collect();

    MultiExpProof {
        t1,
        t2,
        d_list,
        u1,
        u2,
        f_vals,
        z_vals,
    }
}

/// Verify a multi-exponentiation proof.
pub fn multi_exp_verify(
    cs: &[CurvePoint],
    e_list: &[ElGamalCiphertext],
    pf: &MultiExpProof,
) -> bool {
    let n = cs.len();
    if pf.d_list.len() != n || pf.f_vals.len() != n || pf.z_vals.len() != n {
        return false;
    }

    let g = StarkCurve::generator();
    let h = h_generator();

    let e = {
        let mut ts = Transcript::new(b"multi-exp-arg");
        ts.append_points(cs);
        for ct in e_list {
            ts.append_point(&ct.c1);
            ts.append_point(&ct.c2);
        }
        ts.append_points(&pf.d_list);
        ts.append_point(&pf.t1);
        ts.append_point(&pf.t2);
        ts.append_point(&pf.u1);
        ts.append_point(&pf.u2);
        ts.challenge()
    };

    // (i)  z[i]·G + f[i]·H = D[i] + e·cs[i]   ∀i
    for i in 0..n {
        let lhs = g
            .operate_with_self(&pf.z_vals[i].representative())
            .operate_with(&h.operate_with_self(&pf.f_vals[i].representative()));
        let rhs = pf.d_list[i].operate_with(&cs[i].operate_with_self(&e.representative()));
        if lhs != rhs {
            return false;
        }
    }

    // (ii) Σ f[i]·E[i] = U + e·T
    let (lhs1, lhs2) = multi_exp_ct(&pf.f_vals, e_list);
    let rhs1 = pf
        .u1
        .operate_with(&pf.t1.operate_with_self(&e.representative()));
    let rhs2 = pf
        .u2
        .operate_with(&pf.t2.operate_with_self(&e.representative()));
    lhs1 == rhs1 && lhs2 == rhs2
}

// ─────────────────────────────────────────────────────────────────
// Helpers

/// Compute Σ s[i]·E[i] component-wise.
fn multi_exp_ct(scalars: &[FeScalar], cts: &[ElGamalCiphertext]) -> (CurvePoint, CurvePoint) {
    let c1 = scalars
        .iter()
        .zip(cts)
        .fold(CurvePoint::neutral_element(), |acc, (s, ct)| {
            acc.operate_with(&ct.c1.operate_with_self(s.representative()))
        });
    let c2 = scalars
        .iter()
        .zip(cts)
        .fold(CurvePoint::neutral_element(), |acc, (s, ct)| {
            acc.operate_with(&ct.c2.operate_with_self(s.representative()))
        });
    (c1, c2)
}

// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_exp_roundtrip() {
        let n = 4;
        let sk = get_random_fe_scalar();
        let pk = StarkCurve::generator().operate_with_self(&sk.representative());

        // Encrypt n cards
        let cards: Vec<CurvePoint> = (1u64..=n as u64)
            .map(|k| StarkCurve::generator().operate_with_self(k))
            .collect();
        let (cts, _): (Vec<_>, Vec<_>) = cards.iter().map(|m| encrypt(m, &pk).unzip());

        let a_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
        let r_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
        let cs: Vec<CurvePoint> = a_vals
            .iter()
            .zip(&r_vals)
            .map(|(a, r)| commit(a, r))
            .collect();

        let pf = multi_exp_prove(&cs, &a_vals, &r_vals, &cts);
        assert!(multi_exp_verify(&cs, &cts, &pf));
    }
}
