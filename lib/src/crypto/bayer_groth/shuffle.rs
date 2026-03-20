//! §6  Bayer-Groth Shuffle Proof
//!
//! Public inputs:
//!   inputs  = [(C1ᵢ, C2ᵢ)]   n input  ciphertexts
//!   outputs = [(C1'ᵢ, C2'ᵢ)] n output ciphertexts
//!   pk                         ElGamal joint public key
//!
//! Witness (prover only):
//!   perm[i] = j   → outputs[i] is a re-encryption of inputs[j]
//!   rhos[i]       → re-encryption randomness for outputs[i]
//!
//! ──────────────────────────────────────────────────────────────
//! Full protocol (all challenges via Fiat-Shamir):
//!
//!  Round 1  Commit to permutation
//!             c_perm[i] = com(perm[i]; s[i])
//!
//!  Round 2  y-challenges (one per position)
//!             y[i] = FS("y", c_perm, i)
//!
//!  Round 3  Commit to permuted weights
//!             inv_perm[perm[i]] = i
//!             a[j] = y[inv_perm[j]]    ← weight for input j
//!             c_a[j] = com(a[j]; t[j])
//!
//!  Round 4  x-challenge
//!             x = FS("x", c_perm, c_a, y)
//!
//!  Round 5  Product argument
//!             u[j] = x − a[j],  c_u[j] = x·H − c_a[j]
//!             Prove ∏ u[j] = ∏(x − y[i]) = b
//!             ⟹ {a[j]} is a permutation of {y[i]} (Schwartz-Zippel)
//!
//!  Round 6  Multi-exp argument
//!             Prove T_in = Σ a[j]·inputs[j]  under c_a[j]
//!
//!  Round 7  Reveal re-encryption aggregate
//!             R = Σ y[i]·ρ[i]
//!
//!  Verify:
//!    T_out = Σ y[i]·outputs[i]   (verifier computes)
//!    T_in + R·G  = T_out.c1
//!    T_in + R·PK = T_out.c2
//!
//! Correctness:
//!   outputs[i] = inputs[perm[i]] + ρ[i]·(G, PK)
//!   Σ y[i]·outputs[i]
//!     = Σ y[i]·inputs[perm[i]] + (Σ y[i]ρ[i])·(G,PK)
//!     = Σ a[j]·inputs[j]  +  R·(G,PK)       ← since a[j]=y[σ⁻¹(j)]
//!     = T_in               +  R·(G,PK)   ✓

use crate::crypto::bayer_groth::commitment::{commit, h_generator};
use crate::crypto::bayer_groth::multi_exp_arg::{multi_exp_prove, multi_exp_verify, MultiExpProof};
use crate::crypto::bayer_groth::product_arg::{product_prove, product_verify, ProductProof};
use crate::crypto::bayer_groth::transcript::Transcript;
use crate::crypto::elgamal::ElGamalCiphertext;
use crate::utils::get_random_fe_scalar;
use crate::{CurvePoint, Fe, FeScalar};
use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;
use rand_core::{CryptoRng, RngCore};
// ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ShuffleProof {
    /// Commitments to the permutation entries.
    pub c_perm: Vec<CurvePoint>,
    /// Commitments to the permuted y-weights.
    pub c_a: Vec<CurvePoint>,
    /// Product argument (proves {a[j]} is a permutation of {y[i]}).
    pub prod_pf: ProductProof,
    /// Multi-exp argument (proves T_in = Σ a[j]·inputs[j]).
    pub multi_pf: MultiExpProof,
    /// Aggregate re-encryption scalar R = Σ y[i]·ρ[i].
    pub r_enc: FeScalar,
}

/// Error type for failed verifications.
#[derive(Debug, PartialEq, Eq)]
pub enum ShuffleError {
    ProductArgFailed,
    MultiExpArgFailed,
    ReencCheckC1Failed,
    ReencCheckC2Failed,
}

impl std::fmt::Display for ShuffleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProductArgFailed => {
                write!(f, "Product argument failed — not a valid permutation")
            }
            Self::MultiExpArgFailed => write!(f, "Multi-exponentiation argument failed"),
            Self::ReencCheckC1Failed => write!(f, "Re-encryption check failed (C1 component)"),
            Self::ReencCheckC2Failed => write!(f, "Re-encryption check failed (C2 component)"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────

/// Produce a Bayer-Groth shuffle proof.
///
/// `perm[i] = j` means `outputs[i]` is a re-encryption of `inputs[j]`.
/// `rhos[i]`     is the re-encryption randomness for `outputs[i]`.
pub fn shuffle_prove(
    inputs: &[ElGamalCiphertext],
    outputs: &[ElGamalCiphertext],
    perm: &[usize],
    rhos: &[FeScalar],
    pk: &CurvePoint,
) -> ShuffleProof {
    let n = inputs.len();
    assert_eq!(n, outputs.len());
    assert_eq!(n, perm.len());
    assert_eq!(n, rhos.len());

    // ── Round 1: commit to permutation ──────────────────────────
    let s_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
    let c_perm: Vec<CurvePoint> = perm
        .iter()
        .zip(&s_vals)
        .map(|(&pi, s)| commit(&FeScalar::from(pi as u64), s))
        .collect();

    // ── Round 2: y-challenges ────────────────────────────────────
    let y: Vec<FeScalar> = (0..n)
        .map(|i| {
            let mut ts = Transcript::new(b"shuffle-y");
            ts.append_points(&c_perm);
            ts.append_u64(i as u64);
            ts.challenge()
        })
        .collect();

    // ── Round 3: commit to permuted weights ──────────────────────
    // inv_perm[perm[i]] = i  →  a[j] = y[inv_perm[j]]
    let mut inv_perm = vec![0usize; n];
    for i in 0..n {
        inv_perm[perm[i]] = i;
    }
    let a_vals: Vec<FeScalar> = (0..n).map(|j| y[inv_perm[j]]).collect();
    let t_vals: Vec<FeScalar> = (0..n).map(|_| get_random_fe_scalar()).collect();
    let c_a: Vec<CurvePoint> = a_vals
        .iter()
        .zip(&t_vals)
        .map(|(a, t)| commit(a, t))
        .collect();

    // ── Round 4: x-challenge ─────────────────────────────────────
    let x = {
        let mut ts = Transcript::new(b"shuffle-x");
        ts.append_points(&c_perm);
        ts.append_points(&c_a);
        ts.append_scalars(&y);
        ts.challenge()
    };

    // ── Round 5: product argument ─────────────────────────────────
    // u[j] = x − a[j],  committed as  x·H − c_a[j] = com(x−a[j]; −t[j])
    let h = h_generator();
    let u_vals: Vec<FeScalar> = a_vals.iter().map(|a| x - a).collect();
    let u_r: Vec<FeScalar> = t_vals.iter().map(|t| -t).collect();
    let u_comms: Vec<CurvePoint> = c_a
        .iter()
        .map(|ca| h.operate_with_self(&x).operate_with(&ca.neg()))
        .collect();

    // b = ∏(x − y[i])  — verifier can recompute this
    let b_prod = y.iter().fold(FeScalar::one(), |acc, yi| acc * (x - yi));

    let prod_pf = product_prove(&u_comms, &u_vals, &u_r, &b_prod);

    // ── Round 6: multi-exp argument ───────────────────────────────
    // Prove T_in = Σ a[j]·inputs[j]
    let multi_pf = multi_exp_prove(&c_a, &a_vals, &t_vals, inputs);

    // ── Round 7: aggregate re-encryption scalar ───────────────────
    // R = Σ y[i]·ρ[i]   — safe because ρ[i] are uniformly random
    let r_enc = y
        .iter()
        .zip(rhos)
        .fold(FeScalar::zero(), |acc, (yi, rho)| acc + yi * rho);

    ShuffleProof {
        c_perm,
        c_a,
        prod_pf,
        multi_pf,
        r_enc,
    }
}

// ─────────────────────────────────────────────────────────────────

/// Verify a Bayer-Groth shuffle proof.
///
/// Returns `Ok(())` on success or `Err(ShuffleError)` explaining
/// which sub-check failed.
pub fn shuffle_verify(
    inputs: &[ElGamalCiphertext],
    outputs: &[ElGamalCiphertext],
    pk: &CurvePoint,
    pf: &ShuffleProof,
) -> Result<(), ShuffleError> {
    let n = inputs.len();
    let g = StarkCurve::generator();
    let h = h_generator();

    // ── Recompute all Fiat-Shamir challenges (never trust prover) ─
    let y: Vec<FeScalar> = (0..n)
        .map(|i| {
            let mut ts = Transcript::new(b"shuffle-y");
            ts.append_points(&pf.c_perm);
            ts.append_u64(i as u64);
            ts.challenge()
        })
        .collect();

    let x = {
        let mut ts = Transcript::new(b"shuffle-x");
        ts.append_points(&pf.c_perm);
        ts.append_points(&pf.c_a);
        ts.append_scalars(&y);
        ts.challenge()
    };

    // ── Round 5: product argument ─────────────────────────────────
    let u_comms: Vec<CurvePoint> = pf.c_a.iter().map(|ca| h * &x - ca).collect();
    let b_prod = y.iter().fold(FeScalar::one(), |acc, yi| acc * (x - yi));

    if !product_verify(&u_comms, &b_prod, &pf.prod_pf) {
        return Err(ShuffleError::ProductArgFailed);
    }

    // ── Round 6: multi-exp argument ───────────────────────────────
    if !multi_exp_verify(&pf.c_a, inputs, &pf.multi_pf) {
        return Err(ShuffleError::MultiExpArgFailed);
    }

    // ── Final re-encryption check ─────────────────────────────────
    // T_out = Σ y[i]·outputs[i]
    let t_out_c1 = y
        .iter()
        .zip(outputs)
        .fold(CurvePoint::neutral_element(), |acc, (yi, ct)| {
            acc.operate_with(&ct.c1.operate_with_self(yi.representative()))
        });
    let t_out_c2 = y
        .iter()
        .zip(outputs)
        .fold(CurvePoint::neutral_element(), |acc, (yi, ct)| {
            acc.operate_with(&ct.c2.operate_with_self(yi.representative()))
        });

    let t_in_c1 = pf.multi_pf.t1;
    let t_in_c2 = pf.multi_pf.t2;

    // T_in_c1 + R·G  =? T_out_c1
    if t_in_c1.operate_with(&g.operate_with_self(&pf.r_enc.representative())) != t_out_c1 {
        return Err(ShuffleError::ReencCheckC1Failed);
    }
    // T_in_c2 + R·PK =? T_out_c2
    if t_in_c2.operate_with(&pk.operate_with_self(&pf.r_enc)) != t_out_c2 {
        return Err(ShuffleError::ReencCheckC2Failed);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::deck::CardTable;
    use rand::rngs::ThreadRng;
    use rand::seq::SliceRandom;

    fn make_shuffle(
        n: usize,
    ) -> (
        Vec<ElGamalCiphertext>, // inputs
        Vec<ElGamalCiphertext>, // outputs
        Vec<usize>,             // perm
        Vec<FeScalar>,          // rhos
        CurvePoint,             // pk
    ) {
        let sk = get_random_fe_scalar();
        let pk = StarkCurve::generator().operate_with_self(&sk.representative());

        // Encrypt n cards
        let inputs: Vec<ElGamalCiphertext> = (1..=n as u64)
            .map(|k| ElGamalCiphertext::encrypt(&pk, &CardTable::encode_card(Fe::from(k)).x()))
            .collect();

        // Random permutation
        let mut perm: Vec<usize> = (0..n).collect();
        let mut rng = ThreadRng::default();
        perm.shuffle(&mut rng);

        // Re-encrypt in permuted order
        let mut outputs = Vec::with_capacity(n);
        let mut rhos = Vec::with_capacity(n);
        for i in 0..n {
            let (ct, rho) = ElGamalCiphertext::reencrypt(&inputs[perm[i]], &pk);
            outputs.push(ct);
            rhos.push(rho);
        }

        (inputs, outputs, perm, rhos, pk)
    }

    #[test]
    fn shuffle_proof_valid_n4() {
        let (inputs, outputs, perm, rhos, pk) = make_shuffle(4);
        let pf = shuffle_prove(&inputs, &outputs, &perm, &rhos, &pk);
        assert_eq!(shuffle_verify(&inputs, &outputs, &pk, &pf), Ok(()));
    }

    #[test]
    fn shuffle_proof_valid_n8() {
        let (inputs, outputs, perm, rhos, pk) = make_shuffle(8);
        let pf = shuffle_prove(&inputs, &outputs, &perm, &rhos, &pk);
        assert_eq!(shuffle_verify(&inputs, &outputs, &pk, &pf), Ok(()));
    }

    #[test]
    fn shuffle_proof_tampered_output_rejected() {
        let (inputs, mut outputs, perm, rhos, pk) = make_shuffle(4);
        let pf = shuffle_prove(&inputs, &outputs, &perm, &rhos, &pk);
        // Corrupt the first output ciphertext
        outputs[0].c1 = outputs[0].c1.operate_with(&StarkCurve::generator());
        assert!(shuffle_verify(&inputs, &outputs, &pk, &pf).is_err());
    }

    #[test]
    fn shuffle_proof_wrong_perm_rejected() {
        let (inputs, outputs, mut perm, rhos, pk) = make_shuffle(4);
        // Swap two entries in the claimed permutation
        perm.swap(0, 1);
        // Build fresh rhos (so the prover doesn't crash)
        let bad_rhos: Vec<FeScalar> = (0..4).map(|_| get_random_fe_scalar()).collect();
        let bad_pf = shuffle_prove(&inputs, &outputs, &perm, &bad_rhos, &pk);
        assert!(shuffle_verify(&inputs, &outputs, &pk, &bad_pf).is_err());
    }

    #[test]
    fn shuffle_proof_wrong_pk_rejected() {
        let (inputs, outputs, perm, rhos, pk) = make_shuffle(4);
        let pf = shuffle_prove(&inputs, &outputs, &perm, &rhos, &pk);
        let bad_pk =
            StarkCurve::generator().operate_with_self(get_random_fe_scalar().representative()); // random wrong key
        assert!(shuffle_verify(&inputs, &outputs, &bad_pk, &pf).is_err());
    }
}
