use crate::{
    assets::player::Account, constants::CURVE_ORDER_FE,
    crypto::{
        ecdsa::{EcdsaError, EcdsaSignature},
        pedersen_dkg::NewPedersenDKGError::SignatureError,
        pedersen_hash::hash_array,
        utils::ec_array_commitment,
    },
    utils::{cairo_short_string_to_fe, get_random_fe, polynomial_evaluation_mod},
    CurvePoint,
    Fe,
};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, Key, KeyInit, OsRng}, Error, XChaCha20Poly1305,
    XNonce,
};
use lambdaworks_crypto::hash::pedersen::{Pedersen, PedersenStarkCurve};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    traits::ByteConversion,
};
use std::collections::HashMap;

/// Pedersen DKG Proof
///
/// - `secret_pok` - Proof of knowledge of the shared secret.
/// - `commitment` - Commitment of the coefficients. The first entry is the commitment of the secret value.
pub struct PedersenDKGProof {
    secret_pok: EcdsaSignature,
    pub commitment: Vec<CurvePoint>,
}

pub enum VerifyDKGError {
    InvalidPoK,
    InvalidDKGShare,
}

impl PedersenDKGProof {
    fn new(commitments: Vec<CurvePoint>, secret_pok: EcdsaSignature) -> Self {
        Self {
            secret_pok,
            commitment: commitments,
        }
    }

    pub fn commitment_hash(&self) -> Fe {
        hash_array(
            &self
                .commitment
                .iter()
                .map(|point| PedersenStarkCurve::hash(point.to_affine().x(), point.to_affine().y()))
                .collect::<Vec<Fe>>(),
        )
    }

    /// Verify Pedersen DKG commitment.
    ///
    /// - `dkg_share` - Received dkg share
    /// - `x` - evaluation point/seat number
    pub fn verify(&self, dkg_share: Fe, x: &Fe) -> Result<(), VerifyDKGError> {
        self.verify_pok()?;

        let acc = self
            .commitment
            .iter()
            .rev()
            .fold(CurvePoint::neutral_element(), |acc, commitment| {
                commitment.operate_with(&acc.operate_with_self(x.representative()))
            });

        let dkg_share_point = StarkCurve::generator().operate_with_self(dkg_share.representative());

        if acc.to_affine() != dkg_share_point.to_affine() {
            return Err(VerifyDKGError::InvalidDKGShare);
        }

        Ok(())
    }

    fn verify_pok(&self) -> Result<(), VerifyDKGError> {
        let secret_commitment = &self.commitment[0];
        self.secret_pok
            .verify(
                &cairo_short_string_to_fe("BlackBox").unwrap().to_bytes_be(),
                &secret_commitment,
            )
            .map_err(|_| VerifyDKGError::InvalidPoK)?;

        Ok(())
    }
}

/// Pedersen Distributed Key Generation
pub struct PedersenDKG {
    pub proof: PedersenDKGProof,
    // address -> share
    pub dkg_shares: HashMap<Fe, Fe>,
}

#[derive(Debug)]
pub enum NewPedersenDKGError {
    InvalidPlayerKey,
    SignatureError(EcdsaError),
}

impl PedersenDKG {
    /// - `sk` - Account's secret key used to generate the Schnorr proof
    /// - `players_accounts` - Players accounts to encrypt their shares
    pub fn new(sk: &Fe, players_accounts: &Vec<&Account>) -> Result<Self, NewPedersenDKGError> {
        let random_coefficients: Vec<Fe> =
            (0..players_accounts.len()).map(|_| get_random_fe()).collect();

        // sign a message with the secret part of the polynomial to prove knowledge
        let secret_pok = EcdsaSignature::sign(
            &cairo_short_string_to_fe("BlackBox").unwrap().to_bytes_be(),
            &random_coefficients[0],
            None,
        )
            .map_err(|err| SignatureError(err))?;

        let mut dkg_shares = HashMap::new();
        for account in players_accounts.iter() {
            if account.pk == Fe::zero() {
                return Err(NewPedersenDKGError::InvalidPlayerKey);
            }
            let evaluation =
                polynomial_evaluation_mod(&account.address, &random_coefficients, &CURVE_ORDER_FE);
            dkg_shares.insert(account.address, evaluation);
        }

        let commitments = ec_array_commitment(&random_coefficients);

        Ok(Self {
            proof: PedersenDKGProof {
                secret_pok,
                commitment: commitments,
            },
            dkg_shares,
        })
    }
}

#[derive(Clone)]
pub struct EncryptedDKGShare {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

impl EncryptedDKGShare {
    fn new(ciphertext: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self { ciphertext, nonce }
    }

    /// Encrypt DKG share with the player public key.
    /// Returns (ciphertext, nonce)
    pub(crate) fn encrypt_dkg_share(ecdh_secret: &[u8; 32], dkg_share: &[u8]) -> EncryptedDKGShare {
        // TODO: Add authentication
        let cipher = XChaCha20Poly1305::new(<&Key<XChaCha20Poly1305>>::from(ecdh_secret));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, dkg_share.as_ref()).unwrap();

        EncryptedDKGShare::new(ciphertext, nonce.to_vec())
    }

    /// Decrypt DKG share from player
    pub fn decrypt_dkg_share(&self, ecdh_secret: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305::new(<&Key<XChaCha20Poly1305>>::from(ecdh_secret));
        let nonce = XNonce::from_slice(&self.nonce);
        let dkg_share = cipher.decrypt(nonce, self.ciphertext.as_ref())?;

        Ok(dkg_share)
    }
}

#[cfg(test)]
mod tests {
    use crate::{crypto::pedersen_dkg::EncryptedDKGShare, Fe};
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve,
        },
        traits::ByteConversion,
    };

    #[test]
    fn test_encryption_dkg_share() {
        let share = Fe::from(230).to_bytes_be();
        let key = Fe::from(12345678);
        let ecdh_key = StarkCurve::generator()
            .operate_with_self(key.representative())
            .x()
            .to_bytes_be();

        let ciphertext = EncryptedDKGShare::encrypt_dkg_share(&ecdh_key, &share);

        assert_eq!(ciphertext.decrypt_dkg_share(&ecdh_key).unwrap(), share);
    }
}
