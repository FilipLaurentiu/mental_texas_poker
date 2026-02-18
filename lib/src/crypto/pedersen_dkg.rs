use crate::crypto::schnorr_proof::SchnorrProof;
use crate::{utils::get_random_fe_scalar, CurvePoint, FE};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    field::{
        element::FieldElement, fields::fft_friendly::stark_252_prime_field::Stark252PrimeField,
    },
    polynomial::Polynomial,
    traits::ByteConversion,
};

/// Pedersen DKG Proof
///
/// - `secret_pok` - Proof of knowledge of the shared secret.
/// - `commitment` - Commitment of the coefficients. The first entry is the commitment of the secret value.
pub struct PedersenDKGProof {
    secret_pok: SchnorrProof,
    pub commitments: Vec<CurvePoint>,
}

impl PedersenDKGProof {
    fn new(commitments: Vec<CurvePoint>, secret_pok: SchnorrProof) -> Self {
        Self {
            secret_pok,
            commitments,
        }
    }

    pub fn size(&self) -> usize {
        self.commitments.len() - 1
    }

    /// Verify Pedersen DKG commitment.
    ///
    /// - `dkg_share` - Received dkg share
    /// - `pub_key` - Sender public key
    pub fn verify(&self, dkg_share: FE, pub_key: &CurvePoint) -> bool {
        let dkg_polynomial_degree = self.size();

        let mut x = dkg_share.clone();
        let acc = StarkCurve::generator();
        for i in 1..dkg_polynomial_degree {
            let coefficient_commitment = self.commitments.get(i).unwrap();
            acc.operate_with(&coefficient_commitment.operate_with_self(x.representative()));
            x = x.double();
        }
        let dkg_share_point = StarkCurve::generator().operate_with_self(dkg_share.representative());

        self.secret_pok.verify_signature(pub_key) && acc == dkg_share_point
    }
}

/// Pedersen Distributed Key Generation
pub struct PedersenDKG {
    coefficients: Vec<FE>,
    pub proof: PedersenDKGProof,
    pub partial_shares: Vec<FE>,
}

impl PedersenDKG {
    /// - `n` - polynomial degree
    pub fn new(n: usize, private_key: &FE) -> Self {
        let mut random_coefficients: Vec<FE> = Vec::with_capacity(n);
        random_coefficients.fill_with(get_random_fe_scalar);

        let polynomial = Polynomial::new(&random_coefficients);

        let mut commitments = vec![];
        let mut partial_shares = vec![];
        let g = StarkCurve::generator();

        // commitment of the secret value, the constant part of the polynomial, f(0).
        let secret = random_coefficients.first().unwrap();
        commitments.push(g.clone().operate_with_self(secret.representative()));

        for i in 1..n + 1 {
            let field_el =
                FieldElement::<Stark252PrimeField>::from_bytes_be(&i.to_be_bytes()).unwrap();
            let evaluation = polynomial.evaluate(&field_el);
            partial_shares.push(evaluation);
            let commitment = g
                .clone()
                .operate_with_self(random_coefficients.get(i).unwrap().representative());
            commitments.push(commitment);
        }

        let secret_pok = SchnorrProof::sign_message(private_key, secret);

        Self {
            coefficients: random_coefficients,
            proof: PedersenDKGProof {
                secret_pok,
                commitments,
            },
            partial_shares,
        }
    }
}
