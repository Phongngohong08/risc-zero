use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::Date;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// Base64 of 32-byte Ed25519 public key.
    #[serde(rename = "publicKeyBase64")]
    pub public_key_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    pub id: String,
    pub issuer: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    /// ISO8601 date (YYYY-MM-DD).
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "expirationDate")]
    pub expiration_date: Option<String>,
    pub proof: CredentialProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: String,
    /// ISO8601 date (YYYY-MM-DD). Used for age predicate in this PoC.
    pub dob: Option<String>,
    #[serde(rename = "creditScore")]
    pub credit_score: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    /// Base64 of Ed25519 signature over the VC signable payload.
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// Hex-encoded 32 bytes.
    pub nonce: String,
    pub predicate: Predicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Predicate {
    #[serde(rename = "ageOver")]
    AgeOver { min_age: u8, as_of: String },
    #[serde(rename = "creditScoreAtLeast")]
    CreditScoreAtLeast { min_score: u32 },
}

/// What the verifier will read from the receipt journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJournal {
    pub vc_id: String,
    pub issuer_did: String,
    pub nonce: String,
    pub predicate: Predicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverInput {
    pub vc: VerifiableCredential,
    pub issuer_pubkey_base64: String,
    pub challenge: Challenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierExpectation {
    pub challenge: Challenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcSignablePayload {
    pub id: String,
    pub issuer: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "expirationDate")]
    pub expiration_date: Option<String>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn parse_hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("nonce must be hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn parse_date_ymd(s: &str) -> Result<Date> {
    Date::parse(s, &time::format_description::well_known::Iso8601::DATE)
        .with_context(|| format!("invalid date: {s}"))
}

pub fn vc_signable_payload(vc: &VerifiableCredential) -> VcSignablePayload {
    VcSignablePayload {
        id: vc.id.clone(),
        issuer: vc.issuer.clone(),
        credential_subject: vc.credential_subject.clone(),
        issuance_date: vc.issuance_date.clone(),
        expiration_date: vc.expiration_date.clone(),
    }
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // This is deterministic as long as we only use structs / sequences (no maps).
    serde_json::to_vec(value).context("serialize json")
}

pub fn sign_vc(vc: &mut VerifiableCredential, issuer_did: &str, vm_id: &str, sk: &SigningKey) -> Result<()> {
    vc.issuer = issuer_did.to_string();
    let payload = vc_signable_payload(vc);
    let msg = canonical_json_bytes(&payload)?;
    let sig: Signature = sk.sign(&msg);
    vc.proof = CredentialProof {
        ty: "Ed25519Signature".to_string(),
        verification_method: vm_id.to_string(),
        signature: B64.encode(sig.to_bytes()),
    };
    Ok(())
}

pub fn verify_vc_signature(vc: &VerifiableCredential, issuer_vk: &VerifyingKey) -> Result<()> {
    if vc.proof.ty != "Ed25519Signature" {
        return Err(anyhow!("unsupported proof type: {}", vc.proof.ty));
    }
    let payload = vc_signable_payload(vc);
    let msg = canonical_json_bytes(&payload)?;
    let sig_bytes = B64
        .decode(vc.proof.signature.as_bytes())
        .context("decode base64 signature")?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| anyhow!("invalid signature bytes: {e}"))?;
    issuer_vk
        .verify_strict(&msg, &sig)
        .map_err(|e| anyhow!("signature verification failed: {e}"))?;
    Ok(())
}

pub fn decode_ed25519_pubkey_base64(s: &str) -> Result<VerifyingKey> {
    let bytes = B64.decode(s.as_bytes()).context("decode base64 pubkey")?;
    let len = bytes.len();
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte Ed25519 pubkey, got {}", len))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

pub fn encode_ed25519_pubkey_base64(vk: &VerifyingKey) -> String {
    B64.encode(vk.to_bytes())
}

