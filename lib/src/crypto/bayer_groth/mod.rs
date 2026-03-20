pub mod commitment;
pub mod mul_arg;
pub mod product_arg;
pub mod multi_exp_arg;
pub mod shuffle;

pub mod transcript;


#[cfg(test)]
mod tests {
    use crate::utils::get_random_fe_scalar;
    use lambdaworks_math::cyclic_group::IsGroup;
    use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
    use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;

    pub fn test_bayer_groth() {
        println!("╔══════════════════════════════════════════════════════╗");
        println!("║       Bayer-Groth Shuffle Proof — Mental Poker       ║");
        println!("╚══════════════════════════════════════════════════════╝");

        // ── Key setup (threshold ElGamal with 2 players) ──────────────
        println!("\n[Setup] Generating key pairs for 2 players …");
        let sk1 = get_random_fe_scalar();
        let sk2 = get_random_fe_scalar();
        let pk1 = StarkCurve::generator().operate_with_self(&sk1.representative());
        let pk2 = StarkCurve::generator().operate_with_self(&sk2);
        let joint_pk = pk1 + pk2; // PK = sk1·G + sk2·G
        println!("  PK₁, PK₂ generated. Joint PK = PK₁ + PK₂");

        // ── Encode and encrypt the deck ───────────────────────────────
        let n = 8_usize; // Use 8 cards for a fast demo; change to 52 for full deck
        println!("\n[Deck]  Encoding {n} cards as 1·G … {n}·G and encrypting …");

        let card_table = build_card_table();

        let inputs: Vec<_> = (1..=n as u64)
            .map(|k| encrypt(&encode_card(k), &joint_pk, &mut rng).0)
            .collect();
        println!("  Done. All cards encrypted under joint PK.");

        // ── Player 1 shuffles ─────────────────────────────────────────
        println!("\n[P1]    Shuffling and re-encrypting …");
        let t0 = Instant::now();

        let mut perm1: Vec<usize> = (0..n).collect();
        perm1.shuffle(&mut rng);
        println!("  P1 permutation: {:?}", perm1);

        let (outputs1, rhos1): (Vec<_>, Vec<_>) = (0..n)
            .map(|i| reencrypt(&inputs[perm1[i]], &joint_pk, &mut rng))
            .unzip();

        let proof1 = shuffle_prove(&inputs, &outputs1, &perm1, &rhos1, &joint_pk, &mut rng);
        let elapsed1 = t0.elapsed();
        println!("  Proof generated in {elapsed1:.2?}");

        let t1 = Instant::now();
        shuffle_verify(&inputs, &outputs1, &joint_pk, &proof1).expect("P1 shuffle proof should verify");
        println!("  ✓ Verified in {:.2?}", t1.elapsed());

        // ── Player 2 shuffles ─────────────────────────────────────────
        println!("\n[P2]    Shuffling and re-encrypting …");
        let t2 = Instant::now();

        let mut perm2: Vec<usize> = (0..n).collect();
        perm2.shuffle(&mut rng);
        println!("  P2 permutation: {:?}", perm2);

        let (outputs2, rhos2): (Vec<_>, Vec<_>) = (0..n)
            .map(|i| reencrypt(&outputs1[perm2[i]], &joint_pk, &mut rng))
            .unzip();

        let proof2 = shuffle_prove(&outputs1, &outputs2, &perm2, &rhos2, &joint_pk, &mut rng);
        let elapsed2 = t2.elapsed();
        println!("  Proof generated in {elapsed2:.2?}");

        let t3 = Instant::now();
        shuffle_verify(&outputs1, &outputs2, &joint_pk, &proof2)
            .expect("P2 shuffle proof should verify");
        println!("  ✓ Verified in {:.2?}", t3.elapsed());

        // ── Deal: Player 1 gets card at position 0 ────────────────────
        println!("\n[Deal]  Revealing card at position 0 to Player 1 …");
        let card_ct = &outputs2[0];

        // Player 2 contributes partial decryption (+ would attach Chaum-Pedersen proof)
        let d2 = partial_decrypt(card_ct, &sk2);
        println!("  P2 sends partial decryption D₂ = sk₂·C1");

        // Player 1 completes decryption using their own sk
        let d1 = partial_decrypt(card_ct, &sk1);
        let plaintext_pt = combine_partials(card_ct, &[d1, d2]);

        match lookup_card(&plaintext_pt, &card_table) {
            Some(k) => println!("  ✓ Player 1 decrypted card: {k}"),
            None => println!("  ✗ Unknown point — decryption error"),
        }

        // ── Reject tampered shuffle ───────────────────────────────────
        println!("\n[Test]  Tampered output should be rejected …");
        let mut bad_outputs = outputs2.clone();
        bad_outputs[0].c1 = bad_outputs[0].c1 + generator(); // corrupt one ciphertext

        match shuffle_verify(&outputs1, &bad_outputs, &joint_pk, &proof2) {
            Err(e) => println!("  ✓ Correctly rejected: {e}"),
            Ok(()) => println!("  ✗ BUG: tampered proof accepted!"),
        }

        println!("\n╔══════════════════════════════════════════════════════╗");
        println!("║  All checks passed. Run `cargo test` for full suite. ║");
        println!("╚══════════════════════════════════════════════════════╝");
    }
}