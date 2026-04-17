use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use common::{Challenge, ProverInput, VerifiableCredential};
use risc0_host::{prove, receipt_to_bytes, verify};
use vdr_local::VdrStore;

#[derive(Debug, Parser)]
#[command(name = "holder-cli")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate a zkVM proof (receipt) for a VC + challenge.
    Prove {
        #[arg(long, default_value = "./data/vdr.json")]
        vdr: PathBuf,
        #[arg(long)]
        vc: PathBuf,
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long, default_value = "./data/session/receipt.bin")]
        out_receipt: PathBuf,
        #[arg(long, default_value = "./data/session/proof_output.json")]
        out_output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Prove {
            vdr,
            vc,
            challenge,
            out_receipt,
            out_output,
        } => cmd_prove(vdr, vc, challenge, out_receipt, out_output),
    }
}

fn cmd_prove(
    vdr_path: PathBuf,
    vc_path: PathBuf,
    challenge_path: PathBuf,
    out_receipt: PathBuf,
    out_output: PathBuf,
) -> Result<()> {
    let vc_bytes = fs::read(&vc_path).with_context(|| format!("read vc: {vc_path:?}"))?;
    let vc: VerifiableCredential = serde_json::from_slice(&vc_bytes).context("parse vc json")?;

    let ch_bytes =
        fs::read(&challenge_path).with_context(|| format!("read challenge: {challenge_path:?}"))?;
    let challenge: Challenge = serde_json::from_slice(&ch_bytes).context("parse challenge json")?;

    let vdr = VdrStore::load_or_default(&vdr_path)?;
    let doc = vdr
        .get_issuer_did_doc(&vc.issuer)
        .ok_or_else(|| anyhow!("issuer DID not found in VDR: {}", vc.issuer))?;
    let vm = doc
        .verification_method
        .first()
        .ok_or_else(|| anyhow!("issuer DID document has no verificationMethod"))?;

    let input = ProverInput {
        vc,
        issuer_pubkey_base64: vm.public_key_base64.clone(),
        challenge,
    };

    let receipt = prove(&input)?;
    let journal = verify(&receipt)?;

    if let Some(parent) = out_receipt.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    fs::write(&out_receipt, receipt_to_bytes(&receipt)?)
        .with_context(|| format!("write receipt: {out_receipt:?}"))?;

    if let Some(parent) = out_output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    fs::write(&out_output, serde_json::to_vec_pretty(&journal)?)
        .with_context(|| format!("write proof output: {out_output:?}"))?;

    eprintln!("Wrote receipt to {out_receipt:?}");
    eprintln!("Wrote proof output to {out_output:?}");
    Ok(())
}

