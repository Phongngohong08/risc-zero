# RISC0 DID/VC PoC (local-only)

PoC nhỏ theo paper `arXiv:2510.09715`:

- **VDR**: mock bằng file JSON local (`./data/vdr.json`)
- **Issuer**: tạo DID Document + issue 1 VC (DOB) và ký Ed25519
- **Holder**: tạo **zkVM receipt** chứng minh predicate đúng (ageOver) mà không lộ DOB
- **Verifier**: verify receipt + check receipt bind với challenge nonce (chống replay)

## Prerequisites

Bạn cần Rust + toolchain của RISC0:

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y
. "$HOME/.cargo/env"

cargo install rzup
rzup install rust
rzup install r0vm
```

## Build

```bash
. "$HOME/.cargo/env"
cargo build
```

## End-to-end demo (PASS)

```bash
. "$HOME/.cargo/env"
rm -rf ./data

# 1) Issuer init (writes VDR + issuer keys)
cargo run -p issuer-cli -- init

# 2) Issue VC to holder
cargo run -p issuer-cli -- issue --holder did:local:holder1 --dob 2000-01-01

# 3) Verifier creates a challenge (nonce + ageOver predicate)
cargo run -p verifier-cli -- challenge

# 4) Holder proves inside RISC0 zkVM (writes receipt + proof_output.json)
cargo run -p holder-cli -- prove --vc ./data/holder/vc.json --challenge ./data/session/challenge.json

# 5) Verifier verifies receipt and checks nonce/predicate match
cargo run -p verifier-cli -- verify --receipt ./data/session/receipt.bin --challenge ./data/session/challenge.json
```

Kỳ vọng:
- `verifier-cli verify` in ra `PASS`
- `./data/session/proof_output.json` (journal) chỉ chứa `vc_id`, `issuer_did`, `nonce`, `predicate` (không có DOB)

### Dev mode (nhanh, không an toàn)

Nếu bước prove quá lâu trên VM yếu, bạn có thể chạy dev mode. Lưu ý: **dev mode không tạo proof hợp lệ**,
verifier sẽ phải skip receipt verification.

```bash
RISC0_DEV_MODE=1 cargo run -p holder-cli --release -- prove --vc ./data/holder/vc.json --challenge ./data/session/challenge.json
RISC0_DEV_MODE=1 cargo run -p verifier-cli -- verify --receipt ./data/session/receipt.bin --challenge ./data/session/challenge.json
# (hoặc) cargo run -p verifier-cli -- verify --dev-mode --receipt ./data/session/receipt.bin --challenge ./data/session/challenge.json
```

## FAIL cases

### 1) Tamper VC (signature invalid)

Sửa bất kỳ field trong `./data/holder/vc.json` (ví dụ đổi `issuanceDate`), rồi prove lại:

```bash
. "$HOME/.cargo/env"
cargo run -p holder-cli -- prove --vc ./data/holder/vc.json --challenge ./data/session/challenge.json
```

Kỳ vọng: prove sẽ fail do guest verify signature không qua.

### 2) Replay / wrong challenge (nonce mismatch)

Tạo challenge mới rồi verify receipt cũ bằng challenge mới:

```bash
. "$HOME/.cargo/env"

# challenge2
cargo run -p verifier-cli -- challenge --out ./data/session/challenge2.json

# verify old receipt with new challenge -> FAIL
cargo run -p verifier-cli -- verify --receipt ./data/session/receipt.bin --challenge ./data/session/challenge2.json
```

Kỳ vọng: `FAIL` với lý do `nonce mismatch`.

## Code map

- **Data models (DID/VC/Challenge/Journal)**: `crates/common/src/lib.rs`
- **VDR local store**: `crates/vdr-local/src/lib.rs`
- **Issuer CLI**: `crates/issuer-cli/src/main.rs`
- **Holder CLI**: `crates/holder-cli/src/main.rs`
- **Verifier CLI**: `crates/verifier-cli/src/main.rs`
- **zkVM guest**: `risc0/methods/guest/src/main.rs`
- **RISC0 host wrapper**: `risc0/host/src/lib.rs`

