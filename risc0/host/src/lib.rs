use anyhow::{Context, Result};
use common::{ProofJournal, ProverInput};
use risc0_methods::{VDR_POC_GUEST_ELF, VDR_POC_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

pub fn prove(input: &ProverInput) -> Result<Receipt> {
    let env = ExecutorEnv::builder()
        .write(input)
        .context("write prover input")?
        .build()
        .context("build executor env")?;

    let prover = default_prover();
    let receipt = prover
        .prove(env, VDR_POC_GUEST_ELF)
        .context("prove in zkvm")?
        .receipt;

    Ok(receipt)
}

pub fn verify(receipt: &Receipt) -> Result<ProofJournal> {
    receipt.verify(VDR_POC_GUEST_ID).context("receipt verify")?;
    let journal: ProofJournal = receipt.journal.decode().context("decode journal")?;
    Ok(journal)
}

pub fn receipt_to_bytes(receipt: &Receipt) -> Result<Vec<u8>> {
    let words: Vec<u32> = risc0_zkvm::serde::to_vec(receipt).context("serialize receipt")?;
    Ok(words_to_le_bytes(&words))
}

pub fn receipt_from_bytes(bytes: &[u8]) -> Result<Receipt> {
    let words = le_bytes_to_words(bytes).context("decode receipt bytes")?;
    risc0_zkvm::serde::from_slice(&words).context("deserialize receipt")
}

fn words_to_le_bytes(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn le_bytes_to_words(bytes: &[u8]) -> Result<Vec<u32>> {
    if bytes.len() % 4 != 0 {
        anyhow::bail!("receipt bytes length must be multiple of 4, got {}", bytes.len());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{Challenge, CredentialProof, CredentialSubject, Predicate, VerifiableCredential};

    fn roundtrip<T: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Debug + PartialEq>(
        value: &T,
    ) -> T {
        let words: Vec<u32> = risc0_zkvm::serde::to_vec(value).expect("serialize");
        risc0_zkvm::serde::from_slice(&words).expect("deserialize")
    }

    #[test]
    fn risc0_serde_roundtrip_predicate() {
        let p = Predicate::AgeOver {
            min_age: 18,
            as_of: "2026-01-01".to_string(),
        };
        let out: Predicate = roundtrip(&p);
        assert_eq!(out, p);
    }

    #[test]
    fn risc0_serde_roundtrip_challenge() {
        let c = Challenge {
            nonce: "00".repeat(32),
            predicate: Predicate::AgeOver {
                min_age: 18,
                as_of: "2026-01-01".to_string(),
            },
        };
        let out: Challenge = roundtrip(&c);
        assert_eq!(out, c);
    }

    #[test]
    fn risc0_serde_roundtrip_subject_with_option() {
        let s = CredentialSubject {
            id: "did:local:holder1".to_string(),
            dob: Some("2000-01-01".to_string()),
            credit_score: None,
        };
        let out: CredentialSubject = roundtrip(&s);
        assert_eq!(out, s);
    }

    #[test]
    fn risc0_serde_roundtrip_prover_input() {
        let input = ProverInput {
            vc: VerifiableCredential {
                id: "urn:vc:test".to_string(),
                issuer: "did:local:issuer1".to_string(),
                credential_subject: CredentialSubject {
                    id: "did:local:holder1".to_string(),
                    dob: Some("2000-01-01".to_string()),
                    credit_score: None,
                },
                issuance_date: "2026-01-01".to_string(),
                expiration_date: None,
                proof: CredentialProof {
                    ty: "Ed25519Signature".to_string(),
                    verification_method: "did:local:issuer1#key-1".to_string(),
                    signature: "AA==".to_string(),
                },
            },
            issuer_pubkey_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            challenge: Challenge {
                nonce: "00".repeat(32),
                predicate: Predicate::AgeOver {
                    min_age: 18,
                    as_of: "2026-01-01".to_string(),
                },
            },
        };

        let words: Vec<u32> = risc0_zkvm::serde::to_vec(&input).expect("serialize");
        let decoded: ProverInput = risc0_zkvm::serde::from_slice(&words).expect("deserialize");
        assert_eq!(decoded.challenge.nonce, input.challenge.nonce);
        assert_eq!(decoded.vc.id, input.vc.id);
    }
}

