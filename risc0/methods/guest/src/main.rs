use anyhow::{anyhow, Context, Result};
use common::{parse_date_ymd, parse_hex_32, verify_vc_signature, Predicate, ProofJournal, ProverInput};
use risc0_zkvm::guest::env;
use time::Date;

fn main() {
    if let Err(e) = run() {
        // Panicking is fine: it will make the proof fail to verify.
        panic!("{e:?}");
    }
}

fn run() -> Result<()> {
    let input: ProverInput = env::read();

    // Bind nonce format (32-byte hex).
    let _nonce_bytes = parse_hex_32(&input.challenge.nonce)?;

    // Verify VC signature against issuer public key.
    let issuer_vk = common::decode_ed25519_pubkey_base64(&input.issuer_pubkey_base64)?;
    verify_vc_signature(&input.vc, &issuer_vk)?;

    // Check predicate.
    match &input.challenge.predicate {
        Predicate::AgeOver { min_age, as_of } => {
            let dob = input
                .vc
                .credential_subject
                .dob
                .as_deref()
                .ok_or_else(|| anyhow!("vc missing dob"))?;
            let dob = parse_date_ymd(dob)?;
            let as_of = parse_date_ymd(as_of)?;
            ensure_age_over(dob, as_of, *min_age)?;
        }
        Predicate::CreditScoreAtLeast { min_score } => {
            let score = input
                .vc
                .credential_subject
                .credit_score
                .ok_or_else(|| anyhow!("vc missing creditScore"))?;
            if score < *min_score {
                return Err(anyhow!("creditScore {score} < {min_score}"));
            }
        }
    }

    let journal = ProofJournal {
        vc_id: input.vc.id,
        issuer_did: input.vc.issuer,
        nonce: input.challenge.nonce,
        predicate: input.challenge.predicate,
    };
    env::commit(&journal);
    Ok(())
}

fn ensure_age_over(dob: Date, as_of: Date, min_age: u8) -> Result<()> {
    let mut years = as_of.year() - dob.year();
    // If birthday hasn't happened yet this year, subtract one.
    if (as_of.month(), as_of.day()) < (dob.month(), dob.day()) {
        years -= 1;
    }
    let years_u8: u8 = years
        .try_into()
        .context("age out of range")?;
    if years_u8 < min_age {
        return Err(anyhow!("age {years_u8} < {min_age}"));
    }
    Ok(())
}
