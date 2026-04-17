use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use common::DidDocument;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VdrStore {
    pub issuers: BTreeMap<String, DidDocument>,
}

impl VdrStore {
    pub fn load_or_default(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path).with_context(|| format!("read vdr store: {path:?}"))?;
        let store: Self = serde_json::from_slice(&bytes).context("parse vdr json")?;
        Ok(store)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create vdr parent dir: {parent:?}"))?;
        }
        let tmp = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(self).context("serialize vdr json")?;
        fs::write(&tmp, bytes).with_context(|| format!("write tmp vdr store: {tmp:?}"))?;
        fs::rename(&tmp, path).with_context(|| format!("rename tmp vdr store to: {path:?}"))?;
        Ok(())
    }

    pub fn put_issuer_did_doc(&mut self, doc: DidDocument) {
        self.issuers.insert(doc.id.clone(), doc);
    }

    pub fn get_issuer_did_doc(&self, issuer_did: &str) -> Option<&DidDocument> {
        self.issuers.get(issuer_did)
    }
}

