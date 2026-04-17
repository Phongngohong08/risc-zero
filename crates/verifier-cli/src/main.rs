use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use common::{Challenge, Predicate, VerifierExpectation};
use rand::rngs::OsRng;
use rand::RngCore;
use risc0_host::{receipt_from_bytes, verify};
use time::OffsetDateTime;

#[derive(Debug, Parser)]
#[command(name = "verifier-cli")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create a fresh challenge (nonce + predicate).
    Challenge {
        #[arg(long, default_value = "./data/session/challenge.json")]
        out: PathBuf,
        #[arg(long, default_value_t = 18)]
        min_age: u8,
        /// If omitted, uses today's date (UTC) formatted as YYYY-MM-DD.
        #[arg(long)]
        as_of: Option<String>,
    },
    /// Verify a receipt and check it is bound to the provided challenge.
    Verify {
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long, default_value = "./data/session/verifier_result.json")]
        out: PathBuf,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct VerifierResult {
    ok: bool,
    reason: Option<String>,
    journal: Option<common::ProofJournal>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Challenge {
            out,
            min_age,
            as_of,
        } => cmd_challenge(out, min_age, as_of),
        Cmd::Verify {
            receipt,
            challenge,
            out,
        } => cmd_verify(receipt, challenge, out),
    }
}

fn cmd_challenge(out: PathBuf, min_age: u8, as_of: Option<String>) -> Result<()> {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let as_of = match as_of {
        Some(v) => v,
        None => OffsetDateTime::now_utc()
            .date()
            .format(&time::format_description::well_known::Iso8601::DATE)
            .context("format as_of date")?,
    };

    let challenge = Challenge {
        nonce: hex::encode(nonce),
        predicate: Predicate::AgeOver { min_age, as_of },
    };

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    fs::write(&out, serde_json::to_vec_pretty(&challenge)?)
        .with_context(|| format!("write challenge: {out:?}"))?;

    eprintln!("Wrote challenge to {out:?}");
    Ok(())
}

fn cmd_verify(receipt_path: PathBuf, challenge_path: PathBuf, out: PathBuf) -> Result<()> {
    let receipt_bytes =
        fs::read(&receipt_path).with_context(|| format!("read receipt: {receipt_path:?}"))?;
    let receipt = receipt_from_bytes(&receipt_bytes)?;

    let ch_bytes =
        fs::read(&challenge_path).with_context(|| format!("read challenge: {challenge_path:?}"))?;
    let challenge: Challenge = serde_json::from_slice(&ch_bytes).context("parse challenge json")?;

    let expectation = VerifierExpectation {
        challenge: challenge.clone(),
    };

    let result = match verify(&receipt) {
        Ok(journal) => {
            if journal.nonce != expectation.challenge.nonce {
                VerifierResult {
                    ok: false,
                    reason: Some("nonce mismatch (replay or wrong challenge)".to_string()),
                    journal: Some(journal),
                }
            } else if journal.predicate != expectation.challenge.predicate {
                VerifierResult {
                    ok: false,
                    reason: Some("predicate mismatch".to_string()),
                    journal: Some(journal),
                }
            } else {
                VerifierResult {
                    ok: true,
                    reason: None,
                    journal: Some(journal),
                }
            }
        }
        Err(e) => VerifierResult {
            ok: false,
            reason: Some(format!("receipt verify failed: {e}")),
            journal: None,
        },
    };

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    fs::write(&out, serde_json::to_vec_pretty(&result)?)
        .with_context(|| format!("write verifier result: {out:?}"))?;

    if result.ok {
        println!("PASS");
        Ok(())
    } else {
        println!("FAIL");
        Err(anyhow!(result.reason.unwrap_or_else(|| "unknown".to_string())))
    }
}

