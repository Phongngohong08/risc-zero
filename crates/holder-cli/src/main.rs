use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use common::{Challenge, ProverInput, VerifiableCredential};
use risc0_host::{prove, receipt_to_bytes, verify};
use vdr_local::VdrStore;
use time::OffsetDateTime;

// `holder-cli` is the "prover" side of the flow:
// it takes a Verifiable Credential + verifier challenge, proves the statement inside RISC0 zkVM,
// then writes out the zkVM receipt and the public journal ("proof output") for the verifier to check.

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
        /// Write detailed progress logs to this file (useful when proving takes a long time).
        #[arg(long, default_value = "./data/session/holder_prove.log")]
        log: PathBuf,
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
            log,
        } => cmd_prove(vdr, vc, challenge, out_receipt, out_output, log),
    }
}

fn cmd_prove(
    vdr_path: PathBuf,
    vc_path: PathBuf,
    challenge_path: PathBuf,
    out_receipt: PathBuf,
    out_output: PathBuf,
    log_path: PathBuf,
) -> Result<()> {
    let log = |msg: &str| append_log_line(&log_path, msg);

    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    // Start a fresh log per run to make debugging deterministic.
    fs::write(&log_path, b"").with_context(|| format!("init log file: {log_path:?}"))?;

    log("holder-cli prove: start")?;
    log(&format!("log_path={log_path:?}"))?;
    log(&format!("vc_path={vc_path:?}"))?;
    log(&format!("challenge_path={challenge_path:?}"))?;
    log(&format!("vdr_path={vdr_path:?}"))?;
    log(&format!("out_receipt={out_receipt:?}"))?;
    log(&format!("out_output={out_output:?}"))?;

    // Inputs are JSON files produced by earlier steps (`issuer-cli` and `verifier-cli`).
    log("read vc json: begin")?;
    let vc_bytes = fs::read(&vc_path).with_context(|| format!("read vc: {vc_path:?}"))?;
    let vc: VerifiableCredential = serde_json::from_slice(&vc_bytes).context("parse vc json")?;
    log(&format!("read vc json: ok ({} bytes)", vc_bytes.len()))?;

    log("read challenge json: begin")?;
    let ch_bytes =
        fs::read(&challenge_path).with_context(|| format!("read challenge: {challenge_path:?}"))?;
    let challenge: Challenge = serde_json::from_slice(&ch_bytes).context("parse challenge json")?;
    log(&format!("read challenge json: ok ({} bytes)", ch_bytes.len()))?;

    // We resolve the issuer's public key from the local VDR, using the VC's `issuer` DID.
    // This keeps the zkVM guest input self-contained: the guest gets the VC, challenge, and issuer pubkey.
    log("load VDR + resolve issuer pubkey: begin")?;
    let vdr = VdrStore::load_or_default(&vdr_path)?;
    let doc = vdr
        .get_issuer_did_doc(&vc.issuer)
        .ok_or_else(|| anyhow!("issuer DID not found in VDR: {}", vc.issuer))?;
    let vm = doc
        .verification_method
        .first()
        .ok_or_else(|| anyhow!("issuer DID document has no verificationMethod"))?;
    log("load VDR + resolve issuer pubkey: ok")?;

    let input = ProverInput {
        vc,
        issuer_pubkey_base64: vm.public_key_base64.clone(),
        challenge,
    };

    // This is the expensive step: it runs the guest program in RISC0 zkVM and produces a receipt.
    log("zkVM prove(): begin (this is usually the slow step)")?;
    let receipt = prove(&input)?;
    log("zkVM prove(): ok (receipt produced)")?;

    // Sanity-check receipt locally and extract the public journal.
    // (The verifier will do its own verification later.)
    log("receipt verify + journal decode: begin")?;
    let journal = verify(&receipt)?;
    log("receipt verify + journal decode: ok")?;

    // Outputs are written under `./data/session/` by default so the next CLI step can consume them.
    log("write receipt: begin")?;
    if let Some(parent) = out_receipt.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    fs::write(&out_receipt, receipt_to_bytes(&receipt)?)
        .with_context(|| format!("write receipt: {out_receipt:?}"))?;
    log("write receipt: ok")?;

    log("write proof output (journal): begin")?;
    if let Some(parent) = out_output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    fs::write(&out_output, serde_json::to_vec_pretty(&journal)?)
        .with_context(|| format!("write proof output: {out_output:?}"))?;
    log("write proof output (journal): ok")?;

    eprintln!("Wrote receipt to {out_receipt:?}");
    eprintln!("Wrote proof output to {out_output:?}");
    log("holder-cli prove: done")?;
    Ok(())
}

fn append_log_line(path: &Path, msg: &str) -> Result<()> {
    let ts = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "<ts-format-error>".to_string());
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open log file: {path:?}"))?;
    writeln!(f, "[{ts}] {msg}").context("write log line")?;
    Ok(())
}

