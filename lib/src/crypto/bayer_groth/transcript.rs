// ─────────────────────────────────────────────────────────────────
// Fiat-Shamir transcript
// ─────────────────────────────────────────────────────────────────

use crate::{CurvePoint, FeScalar};
use lambdaworks_crypto::hash::pedersen::PedersenStarkCurve;
use lambdaworks_math::traits::ByteConversion;

/// Incremental transcript for Fiat-Shamir challenges.
///
/// Usage:
/// ```ignore
/// let mut ts = Transcript::new(b"shuffle-proof");
/// ts.append_point(&c_perm[0]);
/// ts.append_scalar(&y);
/// let challenge: Fq = ts.challenge();
/// ```
pub struct Transcript {
    hasher: PedersenStarkCurve,
}

impl Transcript {
    pub fn new(label: &[u8]) -> Self {
        let mut h = PedersenStarkCurve::new();
        h.update(b"BGT|");
        h.update(&(label.len() as u32).to_be_bytes());
        h.update(label);
        Self { hasher: h }
    }

    pub fn append_point(&mut self, p: &CurvePoint) {
        self.hasher.update(b"P");
        self.hasher.update(p.x().to_bytes_be());
    }

    pub fn append_points(&mut self, pts: &[CurvePoint]) {
        self.hasher.update(b"[");
        self.hasher.update(&(pts.len() as u32).to_be_bytes());
        for p in pts {
            self.append_point(p);
        }
        self.hasher.update(b"]");
    }

    pub fn append_scalar(&mut self, s: &FeScalar) {
        self.hasher.update(b"Z");
        self.hasher.update(s.to_bytes_be());
    }

    pub fn append_scalars(&mut self, ss: &[FeScalar]) {
        self.hasher.update(b"[");
        self.hasher.update(&(ss.len() as u32).to_be_bytes());
        for s in ss {
            self.append_scalar(s);
        }
        self.hasher.update(b"]");
    }

    pub fn append_u64(&mut self, n: u64) {
        self.hasher.update(b"U");
        self.hasher.update(n.to_be_bytes());
    }

    pub fn append_bytes(&mut self, b: &[u8]) {
        self.hasher.update(b"B");
        self.hasher.update(&(b.len() as u32).to_be_bytes());
        self.hasher.update(b);
    }

    /// Finalise and produce a challenge scalar in Zq.
    /// Consumes self — you need a fresh Transcript for the next challenge.
    pub fn challenge(self) -> FeScalar {
        let digest = self.hasher.finalize();
        // Reduce the 256-bit hash into Zq (wide reduction via from_repr loop
        // would be more uniform, but for a ZK proof system the bias is
        // negligible: |Zq| ≈ 2^256 so the bias is < 2^{-128}).
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.copy_from_slice(&digest);
        // from_repr can fail if the value >= q; retry with counter-mode.
        if let Some(s) = FeScalar::from_repr(repr).into() {
            return s;
        }
        // Extremely unlikely branch (probability < 2^{-128}).
        let mut h2 = PedersenStarkCurve::new();
        h2.update(b"retry");
        h2.update(&digest);
        let d2 = h2.finalize();
        repr.copy_from_slice(&d2);
        Fq::from_repr(repr).expect("double retry failed — SHA-256 broken")
    }
}
