use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use webplus_plugin_config::PluginManifest;

pub const SIGNATURE_FILENAME: &str = "plugin-signature.json";
const MAX_PLUGIN_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TRUST_STORE_BYTES: u64 = 256 * 1024;
const MAX_TRUST_KEYS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetachedSignatureDocument {
    pub schema_version: u8,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

impl DetachedSignatureDocument {
    pub fn new(key_id: &str, signature_base64: &str) -> Result<Self, TrustError> {
        validate_signing_key_id(key_id)?;
        validate_signature_base64(signature_base64)?;
        Ok(Self {
            schema_version: 1,
            key_id: key_id.to_owned(),
            algorithm: "ed25519".into(),
            signature: signature_base64.to_owned(),
        })
    }

    pub fn validate(&self) -> Result<(), TrustError> {
        if self.schema_version != 1 || self.algorithm != "ed25519" {
            return Err(TrustError::Policy(
                "detached signature must use schema 1 and Ed25519".into(),
            ));
        }
        validate_signing_key_id(&self.key_id)?;
        validate_signature_base64(&self.signature)
    }

    pub fn to_pretty_json(&self) -> Result<Vec<u8>, TrustError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            TrustError::Policy(format!("cannot encode detached signature: {error}"))
        })?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustPurpose {
    CutoverDecision,
    CutoverEvidence,
    Plugin,
    PluginCatalog,
    OriginPolicy,
    ProcessPolicy,
}

impl TrustPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CutoverDecision => "cutover-decision",
            Self::CutoverEvidence => "cutover-evidence",
            Self::Plugin => "plugin",
            Self::PluginCatalog => "plugin-catalog",
            Self::OriginPolicy => "origin-policy",
            Self::ProcessPolicy => "process-policy",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustKeyStatus {
    #[default]
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone)]
struct TrustedKey {
    key: VerifyingKey,
    purposes: BTreeSet<TrustPurpose>,
    status: TrustKeyStatus,
}

#[derive(Debug, Clone)]
pub struct TrustStore {
    keys: HashMap<String, TrustedKey>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustStoreStats {
    pub total: usize,
    pub active: usize,
    pub retired: usize,
    pub revoked: usize,
}

impl TrustStore {
    pub fn load(path: &Path) -> Result<Self, TrustError> {
        let metadata = fs::symlink_metadata(path).map_err(|source| TrustError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_file() || metadata.len() > MAX_TRUST_STORE_BYTES {
            return Err(TrustError::Policy(format!(
                "trust store must be a regular file no larger than {MAX_TRUST_STORE_BYTES} bytes"
            )));
        }
        let bytes = fs::read(path).map_err(|source| TrustError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let document: TrustStoreDocument =
            serde_json::from_slice(&bytes).map_err(|source| TrustError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        if document.schema_version != 2 {
            return Err(TrustError::Policy(format!(
                "unsupported trust-store schema version [{}]",
                document.schema_version
            )));
        }
        if document.keys.len() > MAX_TRUST_KEYS {
            return Err(TrustError::Policy(format!(
                "trust store contains more than {MAX_TRUST_KEYS} keys"
            )));
        }

        let mut keys = HashMap::new();
        for entry in document.keys {
            if entry.key_id.trim() != entry.key_id
                || entry.key_id.is_empty()
                || entry.key_id.chars().count() > 128
                || !entry
                    .key_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(TrustError::Policy(
                    "trust key IDs must be portable identifiers of 1 to 128 characters".into(),
                ));
            }
            if entry.algorithm != "ed25519" {
                return Err(TrustError::Policy(format!(
                    "key [{}] uses unsupported algorithm [{}]",
                    entry.key_id, entry.algorithm
                )));
            }
            let bytes = BASE64.decode(&entry.public_key).map_err(|error| {
                TrustError::Policy(format!(
                    "key [{}] is not valid base64: {error}",
                    entry.key_id
                ))
            })?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
                TrustError::Policy(format!(
                    "key [{}] must contain 32 bytes, found {}",
                    entry.key_id,
                    bytes.len()
                ))
            })?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
                TrustError::Policy(format!("key [{}] is invalid: {error}", entry.key_id))
            })?;
            let purpose_count = entry.purposes.len();
            let purposes = entry.purposes.into_iter().collect::<BTreeSet<_>>();
            if purposes.is_empty() {
                return Err(TrustError::Policy(format!(
                    "key [{}] must declare at least one signing purpose",
                    entry.key_id
                )));
            }
            if purposes.len() != purpose_count {
                return Err(TrustError::Policy(format!(
                    "key [{}] declares a duplicate signing purpose",
                    entry.key_id
                )));
            }
            if keys
                .insert(
                    entry.key_id.clone(),
                    TrustedKey {
                        key,
                        purposes,
                        status: entry.status,
                    },
                )
                .is_some()
            {
                return Err(TrustError::Policy(format!(
                    "duplicate trust key ID [{}]",
                    entry.key_id
                )));
            }
        }
        Ok(Self { keys })
    }

    pub fn stats(&self) -> TrustStoreStats {
        let mut stats = TrustStoreStats {
            total: self.keys.len(),
            ..TrustStoreStats::default()
        };
        for key in self.keys.values() {
            match key.status {
                TrustKeyStatus::Active => stats.active += 1,
                TrustKeyStatus::Retired => stats.retired += 1,
                TrustKeyStatus::Revoked => stats.revoked += 1,
            }
        }
        stats
    }

    /// Validates that every purpose carried by this store still has an active
    /// issuance key and that all caller-required purposes are present. This is
    /// intended for release gates, not runtime verification of old artifacts.
    pub fn ensure_release_ready(
        &self,
        required_purposes: &[TrustPurpose],
    ) -> Result<TrustStoreStats, TrustError> {
        let mut declared = BTreeSet::new();
        let mut active = BTreeSet::new();
        for key in self.keys.values() {
            for purpose in &key.purposes {
                declared.insert(*purpose);
                if key.status == TrustKeyStatus::Active {
                    active.insert(*purpose);
                }
            }
        }
        for purpose in required_purposes {
            if !active.contains(purpose) {
                return Err(TrustError::Policy(format!(
                    "release trust store has no active [{}] issuance key",
                    purpose.as_str()
                )));
            }
        }
        for purpose in declared {
            if !active.contains(&purpose) {
                return Err(TrustError::Policy(format!(
                    "release trust purpose [{}] has no active replacement key",
                    purpose.as_str()
                )));
            }
        }
        Ok(self.stats())
    }

    pub fn ensure_key_can_issue(
        &self,
        purpose: TrustPurpose,
        key_id: &str,
    ) -> Result<(), TrustError> {
        self.key_for(key_id, purpose, KeyUse::NewSignature)
            .map(|_| ())
    }

    pub fn verify(&self, manifest: &PluginManifest) -> Result<(), TrustError> {
        self.verify_plugin(manifest, KeyUse::RuntimeVerification)
    }

    /// Verifies a plugin signature while also requiring an active issuance key.
    /// Runtime loading should use [`Self::verify`] so artifacts signed before a
    /// planned rotation remain usable under a retired key.
    pub fn verify_for_issuance(&self, manifest: &PluginManifest) -> Result<(), TrustError> {
        self.verify_plugin(manifest, KeyUse::NewSignature)
    }

    fn verify_plugin(&self, manifest: &PluginManifest, key_use: KeyUse) -> Result<(), TrustError> {
        let document = read_signature_document(&manifest.plugin_dir)?;

        if document.schema_version != 1 {
            return Err(TrustError::Verification(format!(
                "plugin [{}] uses unsupported signature schema version [{}]",
                manifest.plugin_id, document.schema_version
            )));
        }
        if document.algorithm != "ed25519" {
            return Err(TrustError::Verification(format!(
                "plugin [{}] uses unsupported signature algorithm [{}]",
                manifest.plugin_id, document.algorithm
            )));
        }
        validate_plugin_id(&document.plugin_id)?;
        if document.plugin_id != manifest.plugin_id {
            return Err(TrustError::Verification(format!(
                "signature is for plugin [{}], not [{}]",
                document.plugin_id, manifest.plugin_id
            )));
        }
        let key = self.key_for(&document.key_id, TrustPurpose::Plugin, key_use)?;

        let actual_files = hash_plugin_files(&manifest.plugin_dir)?;
        if document.files != actual_files {
            return Err(TrustError::Verification(format!(
                "plugin [{}] file inventory or SHA-256 digest does not match its signature",
                manifest.plugin_id
            )));
        }

        let payload = SignedPayload {
            schema_version: document.schema_version,
            key_id: document.key_id,
            algorithm: document.algorithm,
            plugin_id: document.plugin_id,
            files: document.files,
        };
        let payload = encode_payload(&payload);
        let signature_bytes = BASE64.decode(&document.signature).map_err(|error| {
            TrustError::Verification(format!(
                "plugin [{}] signature is not valid base64: {error}",
                manifest.plugin_id
            ))
        })?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|error| {
            TrustError::Verification(format!(
                "plugin [{}] signature has an invalid length: {error}",
                manifest.plugin_id
            ))
        })?;
        key.verify(&payload, &signature).map_err(|_| {
            TrustError::Verification(format!(
                "plugin [{}] signature verification failed",
                manifest.plugin_id
            ))
        })
    }

    pub fn verify_detached(
        &self,
        purpose: TrustPurpose,
        key_id: &str,
        payload: &[u8],
        signature_base64: &str,
    ) -> Result<(), TrustError> {
        self.verify_detached_with_key_use(
            purpose,
            key_id,
            payload,
            signature_base64,
            KeyUse::RuntimeVerification,
        )
    }

    /// Verifies a newly issued detached signature and rejects retired keys.
    pub fn verify_detached_for_issuance(
        &self,
        purpose: TrustPurpose,
        key_id: &str,
        payload: &[u8],
        signature_base64: &str,
    ) -> Result<(), TrustError> {
        self.verify_detached_with_key_use(
            purpose,
            key_id,
            payload,
            signature_base64,
            KeyUse::NewSignature,
        )
    }

    fn verify_detached_with_key_use(
        &self,
        purpose: TrustPurpose,
        key_id: &str,
        payload: &[u8],
        signature_base64: &str,
        key_use: KeyUse,
    ) -> Result<(), TrustError> {
        let key = self.key_for(key_id, purpose, key_use)?;
        let signature_bytes = BASE64.decode(signature_base64).map_err(|error| {
            TrustError::Verification(format!("signature is not valid base64: {error}"))
        })?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|error| {
            TrustError::Verification(format!("signature has an invalid length: {error}"))
        })?;
        key.verify(payload, &signature)
            .map_err(|_| TrustError::Verification("detached signature verification failed".into()))
    }

    fn key_for(
        &self,
        key_id: &str,
        purpose: TrustPurpose,
        key_use: KeyUse,
    ) -> Result<&VerifyingKey, TrustError> {
        let trusted = self
            .keys
            .get(key_id)
            .ok_or_else(|| TrustError::Verification(format!("unknown trust key [{key_id}]")))?;
        if !trusted.purposes.contains(&purpose) {
            return Err(TrustError::Verification(format!(
                "trust key [{key_id}] is not authorized for [{}] signatures",
                purpose.as_str()
            )));
        }
        match (trusted.status, key_use) {
            (TrustKeyStatus::Revoked, _) => {
                return Err(TrustError::Verification(format!(
                    "trust key [{key_id}] has been revoked"
                )));
            }
            (TrustKeyStatus::Retired, KeyUse::NewSignature) => {
                return Err(TrustError::Verification(format!(
                    "trust key [{key_id}] is retired and cannot authorize new signatures"
                )));
            }
            (TrustKeyStatus::Active | TrustKeyStatus::Retired, KeyUse::RuntimeVerification)
            | (TrustKeyStatus::Active, KeyUse::NewSignature) => {}
        }
        Ok(&trusted.key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyUse {
    RuntimeVerification,
    NewSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginIdentity {
    pub plugin_id: String,
    pub key_id: String,
}

pub fn read_identity(plugin_dir: &Path) -> Result<PluginIdentity, TrustError> {
    let document = read_signature_document(plugin_dir)?;
    validate_plugin_id(&document.plugin_id)?;
    Ok(PluginIdentity {
        plugin_id: document.plugin_id,
        key_id: document.key_id,
    })
}

#[derive(Debug, Clone)]
pub struct PluginSigningMaterial {
    pub plugin_id: String,
    pub key_id: String,
    pub files: BTreeMap<String, String>,
    pub payload: Vec<u8>,
}

pub fn prepare_signing_material(
    plugin_dir: &Path,
    plugin_id: &str,
    key_id: &str,
) -> Result<PluginSigningMaterial, TrustError> {
    validate_plugin_id(plugin_id)?;
    validate_signing_key_id(key_id)?;
    let plugin_id = plugin_id.to_owned();
    let key_id = key_id.to_owned();
    let files = hash_plugin_files(plugin_dir)?;
    let payload = encode_payload(&SignedPayload {
        schema_version: 1,
        key_id: key_id.clone(),
        algorithm: "ed25519".into(),
        plugin_id: plugin_id.clone(),
        files: files.clone(),
    });
    Ok(PluginSigningMaterial {
        plugin_id,
        key_id,
        files,
        payload,
    })
}

/// Encodes the externally-produced Ed25519 signature into the canonical
/// plugin envelope. The signing key itself never enters this API.
pub fn encode_signature_document(
    material: &PluginSigningMaterial,
    signature_base64: &str,
) -> Result<Vec<u8>, TrustError> {
    validate_signature_base64(signature_base64)?;
    let document = SignatureDocument {
        schema_version: 1,
        key_id: material.key_id.clone(),
        algorithm: "ed25519".into(),
        plugin_id: material.plugin_id.clone(),
        files: material.files.clone(),
        signature: signature_base64.to_owned(),
    };
    serde_json::to_vec_pretty(&document)
        .map_err(|error| TrustError::Policy(format!("cannot encode plugin signature: {error}")))
}

pub fn validate_signing_key_id(key_id: &str) -> Result<(), TrustError> {
    if key_id.trim() != key_id
        || key_id.is_empty()
        || key_id.chars().count() > 128
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(TrustError::Policy(
            "signature key ID must be a portable identifier of 1 to 128 characters".into(),
        ));
    }
    Ok(())
}

fn validate_signature_base64(signature_base64: &str) -> Result<(), TrustError> {
    let signature_bytes = BASE64
        .decode(signature_base64)
        .map_err(|error| TrustError::Policy(format!("signature is not valid base64: {error}")))?;
    Signature::from_slice(&signature_bytes)
        .map_err(|error| TrustError::Policy(format!("signature has an invalid length: {error}")))?;
    Ok(())
}

fn read_signature_document(plugin_dir: &Path) -> Result<SignatureDocument, TrustError> {
    let signature_path = plugin_dir.join(SIGNATURE_FILENAME);
    let bytes = fs::read(&signature_path).map_err(|source| TrustError::Read {
        path: signature_path.clone(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| TrustError::Json {
        path: signature_path,
        source,
    })
}

fn validate_plugin_id(plugin_id: &str) -> Result<(), TrustError> {
    let path = Path::new(plugin_id);
    if plugin_id.trim().is_empty()
        || plugin_id.starts_with('.')
        || plugin_id.chars().count() > 128
        || plugin_id.chars().any(char::is_control)
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
        || plugin_id.contains(['/', '\\'])
    {
        return Err(TrustError::Verification(
            "plugin ID must be a safe single path component of 1 to 128 characters".into(),
        ));
    }
    portable_plugin_path(path)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustStoreDocument {
    schema_version: u8,
    keys: Vec<TrustKeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustKeyDocument {
    key_id: String,
    algorithm: String,
    public_key: String,
    purposes: Vec<TrustPurpose>,
    #[serde(default)]
    status: TrustKeyStatus,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignatureDocument {
    schema_version: u8,
    key_id: String,
    algorithm: String,
    plugin_id: String,
    files: BTreeMap<String, String>,
    signature: String,
}

#[derive(Debug)]
struct SignedPayload {
    schema_version: u8,
    key_id: String,
    algorithm: String,
    plugin_id: String,
    files: BTreeMap<String, String>,
}

fn encode_payload(payload: &SignedPayload) -> Vec<u8> {
    let mut bytes = b"SSDEV-PLUGIN-SIGNATURE\0".to_vec();
    bytes.push(payload.schema_version);
    append_field(&mut bytes, payload.key_id.as_bytes());
    append_field(&mut bytes, payload.algorithm.as_bytes());
    append_field(&mut bytes, payload.plugin_id.as_bytes());
    bytes.extend_from_slice(&(payload.files.len() as u32).to_be_bytes());
    for (path, digest) in &payload.files {
        append_field(&mut bytes, path.as_bytes());
        append_field(&mut bytes, digest.as_bytes());
    }
    bytes
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value);
}

fn hash_plugin_files(root: &Path) -> Result<BTreeMap<String, String>, TrustError> {
    let root = root.canonicalize().map_err(|source| TrustError::Read {
        path: root.to_path_buf(),
        source,
    })?;
    let mut files = BTreeMap::new();
    let mut total_bytes = 0;
    collect_files(&root, &root, &mut files, &mut total_bytes)?;
    if !files.contains_key("api.json") {
        return Err(TrustError::Verification(
            "signed plugin inventory must contain api.json".into(),
        ));
    }
    Ok(files)
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
    total_bytes: &mut u64,
) -> Result<(), TrustError> {
    let entries = fs::read_dir(directory).map_err(|source| TrustError::ReadDirectory {
        path: directory.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| TrustError::ReadDirectory {
            path: directory.to_path_buf(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| TrustError::Read {
            path: entry.path(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(TrustError::Verification(format!(
                "plugin packages must not contain symbolic links: {:?}",
                entry.path()
            )));
        }
        if file_type.is_dir() {
            collect_files(root, &entry.path(), files, total_bytes)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(TrustError::Verification(format!(
                "plugin packages may contain only regular files: {:?}",
                entry.path()
            )));
        }
        let entry_path = entry.path();
        let relative = entry_path.strip_prefix(root).map_err(|_| {
            TrustError::Verification(format!("plugin file escaped package root: {entry_path:?}"))
        })?;
        let relative = portable_plugin_path(relative)?;
        if relative == SIGNATURE_FILENAME {
            continue;
        }
        let length = entry
            .metadata()
            .map_err(|source| TrustError::Read {
                path: entry_path.clone(),
                source,
            })?
            .len();
        *total_bytes = total_bytes.saturating_add(length);
        if *total_bytes > MAX_PLUGIN_BYTES {
            return Err(TrustError::Verification(format!(
                "plugin package exceeds the {} byte limit",
                MAX_PLUGIN_BYTES
            )));
        }
        files.insert(relative, sha256_file(&entry_path)?);
    }
    Ok(())
}

pub fn portable_plugin_path(path: &Path) -> Result<String, TrustError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(|| {
                    TrustError::Verification(format!("plugin paths must be valid UTF-8: {path:?}"))
                })?;
                if !is_portable_component(part) {
                    return Err(TrustError::Verification(format!(
                        "plugin path component is not portable to Windows: {part:?}"
                    )));
                }
                parts.push(part.to_owned());
            }
            _ => {
                return Err(TrustError::Verification(format!(
                    "plugin inventory contains an unsafe path: {path:?}"
                )))
            }
        }
    }
    if parts.is_empty() {
        return Err(TrustError::Verification(
            "plugin inventory contains an empty path".into(),
        ));
    }
    Ok(parts.join("/"))
}

fn is_portable_component(component: &str) -> bool {
    if component.is_empty()
        || component.ends_with('.')
        || component.ends_with(' ')
        || component
            .chars()
            .any(|character| character.is_control() || "<>:\"|?*\\".contains(character))
    {
        return false;
    }
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !matches!(
            stem.strip_prefix("COM")
                .and_then(|value| value.parse::<u8>().ok()),
            Some(1..=9)
        )
        && !matches!(
            stem.strip_prefix("LPT")
                .and_then(|value| value.parse::<u8>().ok()),
            Some(1..=9)
        )
}

fn sha256_file(path: &Path) -> Result<String, TrustError> {
    let mut file = fs::File::open(path).map_err(|source| TrustError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| TrustError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(digest_hex(hasher.finalize()))
}

fn digest_hex(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("failed to read {path:?}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to enumerate {path:?}: {source}")]
    ReadDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid JSON in {path:?}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("invalid plugin trust policy: {0}")]
    Policy(String),
    #[error("plugin trust verification failed: {0}")]
    Verification(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;

    fn signed_plugin() -> (tempfile::TempDir, TrustStore, PluginManifest) {
        signed_plugin_with_status(None)
    }

    fn signed_plugin_with_status(
        status: Option<&str>,
    ) -> (tempfile::TempDir, TrustStore, PluginManifest) {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(root.path().join("reader.dll"), b"fixture DLL").unwrap();

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let payload = SignedPayload {
            schema_version: 1,
            key_id: "test-key".into(),
            algorithm: "ed25519".into(),
            plugin_id: "reader-plugin".into(),
            files: hash_plugin_files(root.path()).unwrap(),
        };
        let payload_bytes = encode_payload(&payload);
        let signature = signing_key.sign(&payload_bytes);
        let document = serde_json::json!({
            "schemaVersion": payload.schema_version,
            "keyId": payload.key_id,
            "algorithm": payload.algorithm,
            "pluginId": payload.plugin_id,
            "files": payload.files,
            "signature": BASE64.encode(signature.to_bytes())
        });
        fs::write(
            root.path().join(SIGNATURE_FILENAME),
            serde_json::to_vec_pretty(&document).unwrap(),
        )
        .unwrap();

        let mut trust_key = serde_json::json!({
            "keyId": "test-key",
            "algorithm": "ed25519",
            "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
            "purposes": ["plugin"]
        });
        if let Some(status) = status {
            trust_key["status"] = serde_json::Value::String(status.to_owned());
        }
        let trust_document = serde_json::json!({
            "schemaVersion": 2,
            "keys": [trust_key]
        });
        let trust_path = root.path().join("trust.json");
        fs::write(&trust_path, serde_json::to_vec(&trust_document).unwrap()).unwrap();
        let trust = TrustStore::load(&trust_path).unwrap();
        fs::remove_file(trust_path).unwrap();
        let manifest = PluginManifest::load("reader-plugin", root.path()).unwrap();
        (root, trust, manifest)
    }

    #[test]
    fn verifies_a_complete_signed_inventory() {
        let (_root, trust, manifest) = signed_plugin();
        trust.verify(&manifest).unwrap();
        trust.verify_for_issuance(&manifest).unwrap();
    }

    #[test]
    fn retired_keys_remain_runtime_compatible_but_cannot_issue_new_signatures() {
        let (_root, trust, manifest) = signed_plugin_with_status(Some("retired"));
        trust.verify(&manifest).unwrap();
        let error = trust.verify_for_issuance(&manifest).unwrap_err();
        assert!(error.to_string().contains("retired"));
    }

    #[test]
    fn revoked_keys_reject_runtime_and_new_plugin_signatures() {
        let (_root, trust, manifest) = signed_plugin_with_status(Some("revoked"));
        assert!(trust
            .verify(&manifest)
            .unwrap_err()
            .to_string()
            .contains("revoked"));
        assert!(trust
            .verify_for_issuance(&manifest)
            .unwrap_err()
            .to_string()
            .contains("revoked"));
    }

    #[test]
    fn trust_store_reports_only_lifecycle_counts() {
        let (_root, active, _manifest) = signed_plugin();
        assert_eq!(
            active.stats(),
            TrustStoreStats {
                total: 1,
                active: 1,
                retired: 0,
                revoked: 0,
            }
        );
        let (_root, retired, _manifest) = signed_plugin_with_status(Some("retired"));
        assert_eq!(retired.stats().retired, 1);
        assert!(retired
            .ensure_release_ready(&[TrustPurpose::Plugin])
            .unwrap_err()
            .to_string()
            .contains("no active"));
        assert!(retired
            .ensure_key_can_issue(TrustPurpose::Plugin, "test-key")
            .unwrap_err()
            .to_string()
            .contains("retired"));
        let (_root, revoked, _manifest) = signed_plugin_with_status(Some("revoked"));
        assert_eq!(revoked.stats().revoked, 1);
        active
            .ensure_release_ready(&[TrustPurpose::Plugin])
            .unwrap();
        active
            .ensure_key_can_issue(TrustPurpose::Plugin, "test-key")
            .unwrap();
        assert!(active
            .ensure_release_ready(&[TrustPurpose::OriginPolicy])
            .is_err());
    }

    #[test]
    fn rejects_files_added_after_signing() {
        let (root, trust, manifest) = signed_plugin();
        fs::write(root.path().join("injected.dll"), b"unexpected").unwrap();

        let error = trust.verify(&manifest).unwrap_err();
        assert!(matches!(error, TrustError::Verification(_)));
    }

    #[test]
    fn rejects_modified_manifest_bytes() {
        let (root, trust, manifest) = signed_plugin();
        fs::write(root.path().join("api.json"), b"{}").unwrap();

        let error = trust.verify(&manifest).unwrap_err();
        assert!(matches!(error, TrustError::Verification(_)));
    }

    #[test]
    fn purpose_scopes_reject_cross_domain_signatures() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
        let trust_path = root.path().join("trust.json");
        fs::write(
            &trust_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "plugin-only",
                    "algorithm": "ed25519",
                    "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["plugin"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let trust = TrustStore::load(&trust_path).unwrap();
        let payload = b"domain-separated-policy-payload";
        let signature = BASE64.encode(signing_key.sign(payload).to_bytes());

        trust
            .verify_detached(TrustPurpose::Plugin, "plugin-only", payload, &signature)
            .unwrap();
        let error = trust
            .verify_detached(
                TrustPurpose::OriginPolicy,
                "plugin-only",
                payload,
                &signature,
            )
            .unwrap_err();
        assert!(error.to_string().contains("origin-policy"));
    }

    #[test]
    fn retired_detached_keys_remain_runtime_compatible_and_revoked_keys_are_blocked() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
        let payload = b"signed-policy";
        let signature = BASE64.encode(signing_key.sign(payload).to_bytes());
        let trust_path = root.path().join("trust.json");

        for (status, runtime_allowed) in [("retired", true), ("revoked", false)] {
            fs::write(
                &trust_path,
                serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": 2,
                    "keys": [{
                        "keyId": "rotating-key",
                        "algorithm": "ed25519",
                        "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
                        "purposes": ["origin-policy"],
                        "status": status
                    }]
                }))
                .unwrap(),
            )
            .unwrap();
            let trust = TrustStore::load(&trust_path).unwrap();
            let runtime = trust.verify_detached(
                TrustPurpose::OriginPolicy,
                "rotating-key",
                payload,
                &signature,
            );
            assert_eq!(runtime.is_ok(), runtime_allowed);
            assert!(trust
                .verify_detached_for_issuance(
                    TrustPurpose::OriginPolicy,
                    "rotating-key",
                    payload,
                    &signature,
                )
                .is_err());
        }
    }

    #[test]
    fn legacy_or_ambiguous_trust_stores_are_rejected() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[37_u8; 32]);
        let trust_path = root.path().join("trust.json");
        let key = serde_json::json!({
            "keyId": "ambiguous",
            "algorithm": "ed25519",
            "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
            "purposes": ["plugin", "plugin"]
        });
        fs::write(
            &trust_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [key]
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(TrustStore::load(&trust_path).is_err());

        fs::write(
            &trust_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "keys": []
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(TrustStore::load(&trust_path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn trust_store_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let target = root.path().join("target.json");
        let link = root.path().join("trust.json");
        fs::write(&target, br#"{"schemaVersion":2,"keys":[]}"#).unwrap();
        symlink(&target, &link).unwrap();
        assert!(TrustStore::load(&link).is_err());
    }
}
