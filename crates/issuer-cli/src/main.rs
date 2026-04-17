use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use common::{
    encode_ed25519_pubkey_base64, sign_vc, CredentialProof, CredentialSubject, DidDocument,
    VerificationMethod, VerifiableCredential,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use time::OffsetDateTime;
use vdr_local::VdrStore;

// Đây là CLI đơn giản của issuer. Nó có hai lệnh chính: `init` và `issue`.
// `init` tạo DID Document và khóa cho issuer.
// `issue` cấp một Verifiable Credential (VC) cho holder dựa trên khóa issuer.
#[derive(Debug, Parser)]
#[command(name = "issuer-cli")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create an issuer DID document in the local VDR and write issuer keys to disk.
    Init {
        #[arg(long, default_value = "./data/vdr.json")]
        vdr: PathBuf,
        #[arg(long, default_value = "./data/issuer/issuer_keys.json")]
        out_keys: PathBuf,
        #[arg(long, default_value = "issuer1")]
        issuer_id: String,
    },
    /// Issue a VC to a holder and write it to disk.
    Issue {
        #[arg(long, default_value = "./data/vdr.json")]
        vdr: PathBuf,
        #[arg(long, default_value = "./data/issuer/issuer_keys.json")]
        issuer_keys: PathBuf,
        #[arg(long)]
        holder: String,
        /// Date of birth (YYYY-MM-DD), used for age predicates.
        #[arg(long)]
        dob: String,
        #[arg(long, default_value = "./data/holder/vc.json")]
        out_vc: PathBuf,
    },
}

// Dữ liệu lưu trữ khóa issuer ở dạng JSON local.
// Trong PoC này chúng ta giữ khóa bí mật trên đĩa, nhưng thực tế nên dùng HSM/KMS.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IssuerKeysFile {
    issuer_did: String,
    verification_method: String,
    /// Base64 của 32-byte Ed25519 secret key seed.
    signing_key_base64: String,
}

fn main() -> Result<()> {
    // Phân tích tham số CLI và gọi hàm tương ứng.
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init {
            vdr,
            out_keys,
            issuer_id,
        } => cmd_init(vdr, out_keys, issuer_id),
        Cmd::Issue {
            vdr,
            issuer_keys,
            holder,
            dob,
            out_vc,
        } => cmd_issue(vdr, issuer_keys, holder, dob, out_vc),
    }
}

fn cmd_init(vdr_path: PathBuf, keys_path: PathBuf, issuer_id: String) -> Result<()> {
    // Tạo DID của issuer. Ở đây dùng phương thức tạm `did:local:`.
    let issuer_did = format!("did:local:{issuer_id}");
    // Thêm fragment `#key-1` để chỉ đến verification method.
    let vm_id = format!("{issuer_did}#key-1");

    // Tạo cặp khóa Ed25519 mới.
    // Ed25519 dễ dùng và đủ cho demo, đồng thời zkVM cũng có thể kiểm tra chữ ký này.
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();

    // Tạo DID Document chỉ chứa public key của issuer.
    let doc = DidDocument {
        id: issuer_did.clone(),
        verification_method: vec![VerificationMethod {
            id: vm_id.clone(),
            ty: "Ed25519VerificationKey2020".to_string(),
            public_key_base64: encode_ed25519_pubkey_base64(&vk),
        }],
    };

    // Nạp hoặc tạo mới store VDR local, ghi DID Document vào.
    let mut store = VdrStore::load_or_default(&vdr_path)?;
    store.put_issuer_did_doc(doc);
    store.save(&vdr_path)?;

    // Tạo thư mục nếu cần rồi ghi file JSON chứa khóa issuer.
    if let Some(parent) = keys_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    let keys = IssuerKeysFile {
        issuer_did,
        verification_method: vm_id,
        signing_key_base64: B64.encode(sk.to_bytes()),
    };
    fs::write(&keys_path, serde_json::to_vec_pretty(&keys)?)
        .with_context(|| format!("write issuer keys: {keys_path:?}"))?;

    eprintln!("Wrote VDR store to {vdr_path:?}");
    eprintln!("Wrote issuer keys to {keys_path:?}");
    Ok(())
}

fn cmd_issue(
    _vdr_path: PathBuf,
    issuer_keys_path: PathBuf,
    holder_did: String,
    dob: String,
    out_vc: PathBuf,
) -> Result<()> {
    // Đọc file issuer key đã lưu từ lệnh `init`.
    let keys_bytes = fs::read(&issuer_keys_path)
        .with_context(|| format!("read issuer keys: {issuer_keys_path:?}"))?;
    let keys: IssuerKeysFile = serde_json::from_slice(&keys_bytes).context("parse issuer keys json")?;

    // Giải mã khóa bí mật từ Base64 rồi chuyển thành array 32 byte.
    let sk_bytes = B64
        .decode(keys.signing_key_base64.as_bytes())
        .context("decode base64 signing key")?;
    let sk_len = sk_bytes.len();
    let sk_arr: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte signing key seed, got {}", sk_len))?;
    let sk = SigningKey::from_bytes(&sk_arr);

    // Tạo ID ngẫu nhiên cho credential. Đây là URN nội bộ, không cần resolvable.
    let mut id_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut id_bytes);
    let vc_id = format!("urn:vc:{}", hex::encode(id_bytes));

    // Lấy ngày hiện tại để ghi issuance_date.
    let issuance_date = OffsetDateTime::now_utc()
        .date()
        .format(&time::format_description::well_known::Iso8601::DATE)
        .context("format issuance date")?;

    // Tạo VC ban đầu chưa có chữ ký.
    let mut vc = VerifiableCredential {
        id: vc_id,
        issuer: keys.issuer_did.clone(),
        credential_subject: CredentialSubject {
            id: holder_did,
            dob: Some(dob),
            credit_score: None,
        },
        issuance_date,
        expiration_date: None,
        proof: CredentialProof {
            ty: "Ed25519Signature".to_string(),
            verification_method: keys.verification_method.clone(),
            signature: "".to_string(),
        },
    };

    // Ký VC bằng hàm chung `sign_vc` để tạo chữ ký deterministic.
    // Điều này giúp host/guest xác nhận cùng một nội dung dữ liệu.
    sign_vc(
        &mut vc,
        &keys.issuer_did,
        &keys.verification_method,
        &sk,
    )?;

    // Ghi VC đã ký ra file JSON.
    if let Some(parent) = out_vc.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dir: {parent:?}"))?;
    }
    fs::write(&out_vc, serde_json::to_vec_pretty(&vc)?)
        .with_context(|| format!("write vc: {out_vc:?}"))?;

    eprintln!("Wrote VC to {out_vc:?}");
    Ok(())
}

