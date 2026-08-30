use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::{Client, Url};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempBuilder, NamedTempFile};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use webplus_plugin_trust::{DetachedSignatureDocument, TrustError, TrustPurpose, TrustStore};

const MAX_CATALOG_BYTES: usize = 4 * 1024 * 1024;
const MAX_CATALOG_ENTRIES: usize = 4096;
const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CATALOG_LIFETIME: u64 = 31 * 24 * 60 * 60;
const CATALOG_DOMAIN: &[u8] = b"SSDEV-PLUGIN-CATALOG\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogEntry {
    pub plugin_id: String,
    pub version: Version,
    #[serde(default)]
    pub desktop_version_requirement: Option<VersionReq>,
    pub url: Url,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogWithdrawalReason {
    Security,
    Defective,
    PublisherWithdrawn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogWithdrawal {
    pub plugin_id: String,
    pub version: Version,
    pub reason: CatalogWithdrawalReason,
}

#[derive(Debug, Clone)]
pub struct PluginCatalog {
    issued_at: u64,
    expires_at: u64,
    signing_key_id: Option<String>,
    entries: Vec<CatalogEntry>,
    withdrawals: Vec<CatalogWithdrawal>,
}

impl PluginCatalog {
    pub fn from_signed_bytes(
        catalog_bytes: &[u8],
        signature_bytes: &[u8],
        trust_store: &TrustStore,
        now: SystemTime,
    ) -> Result<Self, RepositoryError> {
        if catalog_bytes.len() > MAX_CATALOG_BYTES || signature_bytes.len() > MAX_CATALOG_BYTES {
            return Err(RepositoryError::Invalid(
                "catalog or signature exceeds 4 MiB".into(),
            ));
        }
        let signature: DetachedSignatureDocument = serde_json::from_slice(signature_bytes)?;
        signature.validate()?;
        trust_store.verify_detached(
            TrustPurpose::PluginCatalog,
            &signature.key_id,
            &signing_payload(catalog_bytes),
            &signature.signature,
        )?;
        let mut catalog = Self::from_unsigned_bytes(catalog_bytes, now)?;
        catalog.signing_key_id = Some(signature.key_id);
        Ok(catalog)
    }

    /// Validates an unsigned catalog before it is sent to an external signer.
    pub fn from_unsigned_bytes(
        catalog_bytes: &[u8],
        now: SystemTime,
    ) -> Result<Self, RepositoryError> {
        if catalog_bytes.len() > MAX_CATALOG_BYTES {
            return Err(RepositoryError::Invalid("catalog exceeds 4 MiB".into()));
        }
        let document: CatalogDocument = serde_json::from_slice(catalog_bytes)?;
        if document.schema_version != 1 {
            return Err(RepositoryError::Invalid(format!(
                "unsupported catalog schema [{}]",
                document.schema_version
            )));
        }
        if document.entries.len() > MAX_CATALOG_ENTRIES {
            return Err(RepositoryError::Invalid(format!(
                "catalog contains more than {MAX_CATALOG_ENTRIES} entries"
            )));
        }
        if document.withdrawals.len() > MAX_CATALOG_ENTRIES {
            return Err(RepositoryError::Invalid(format!(
                "catalog contains more than {MAX_CATALOG_ENTRIES} withdrawals"
            )));
        }
        if document.expires_at <= document.issued_at
            || document.expires_at - document.issued_at > MAX_CATALOG_LIFETIME
        {
            return Err(RepositoryError::Invalid(
                "catalog validity must be positive and at most 31 days".into(),
            ));
        }
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RepositoryError::Invalid("system clock precedes Unix epoch".into()))?
            .as_secs();
        if now < document.issued_at.saturating_sub(300) || now > document.expires_at {
            return Err(RepositoryError::Invalid(
                "catalog is not currently valid; check clock or refresh catalog".into(),
            ));
        }
        let mut identities = HashSet::new();
        for entry in &document.entries {
            validate_entry(entry)?;
            if !identities.insert((entry.plugin_id.clone(), entry.version.clone())) {
                return Err(RepositoryError::Invalid(format!(
                    "duplicate catalog entry [{} {}]",
                    entry.plugin_id, entry.version
                )));
            }
        }
        let mut withdrawn_identities = HashSet::new();
        for withdrawal in &document.withdrawals {
            validate_withdrawal(withdrawal)?;
            let identity = (withdrawal.plugin_id.clone(), withdrawal.version.clone());
            if !withdrawn_identities.insert(identity.clone()) {
                return Err(RepositoryError::Invalid(format!(
                    "duplicate catalog withdrawal [{} {}]",
                    withdrawal.plugin_id, withdrawal.version
                )));
            }
            if identities.contains(&identity) {
                return Err(RepositoryError::Invalid(format!(
                    "catalog release [{} {}] cannot be both installable and withdrawn",
                    withdrawal.plugin_id, withdrawal.version
                )));
            }
        }
        Ok(Self {
            issued_at: document.issued_at,
            expires_at: document.expires_at,
            signing_key_id: None,
            entries: document.entries,
            withdrawals: document.withdrawals,
        })
    }

    pub fn select(&self, plugin_id: &str, version: Option<&Version>) -> Option<&CatalogEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.plugin_id == plugin_id
                    && version.is_none_or(|version| &entry.version == version)
            })
            .max_by(|left, right| left.version.cmp(&right.version))
    }

    pub fn select_compatible(
        &self,
        plugin_id: &str,
        version: Option<&Version>,
        desktop_version: &Version,
    ) -> Option<&CatalogEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.plugin_id == plugin_id
                    && version.is_none_or(|version| &entry.version == version)
                    && entry
                        .desktop_version_requirement
                        .as_ref()
                        .is_some_and(|requirement| requirement.matches(desktop_version))
            })
            .max_by(|left, right| left.version.cmp(&right.version))
    }

    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    pub fn withdrawals(&self) -> &[CatalogWithdrawal] {
        &self.withdrawals
    }

    pub fn withdrawal(&self, plugin_id: &str, version: &Version) -> Option<&CatalogWithdrawal> {
        self.withdrawals
            .iter()
            .find(|withdrawal| withdrawal.plugin_id == plugin_id && &withdrawal.version == version)
    }

    /// Rejects legacy catalog entries that do not bind a signed plugin release
    /// to an explicit Desktop compatibility range. Runtime parsing remains
    /// tolerant so an old catalog can be diagnosed, but official issuance must
    /// fail closed instead of publishing an entry no client can safely select.
    pub fn ensure_desktop_compatibility_declared(&self) -> Result<(), RepositoryError> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.desktop_version_requirement.is_none())
        {
            return Err(RepositoryError::Invalid(format!(
                "catalog entry [{} {}] does not declare desktopVersionRequirement",
                entry.plugin_id, entry.version
            )));
        }
        Ok(())
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Identifies the trusted key that authenticated a fetched catalog.
    /// Unsigned catalogs parsed by release tooling intentionally return None.
    pub fn signing_key_id(&self) -> Option<&str> {
        self.signing_key_id.as_deref()
    }
}

pub struct DownloadedPackage {
    file: NamedTempFile,
    pub entry: CatalogEntry,
}

impl DownloadedPackage {
    pub fn path(&self) -> &Path {
        self.file.path()
    }
}

pub fn signing_payload(catalog_bytes: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(catalog_bytes);
    let mut payload = Vec::with_capacity(CATALOG_DOMAIN.len() + digest.len());
    payload.extend_from_slice(CATALOG_DOMAIN);
    payload.extend_from_slice(&digest);
    payload
}

/// Encodes a deterministic catalog from package-derived entries and validates
/// it with the same rules used by the runtime before returning any bytes.
pub fn encode_catalog_document(
    issued_at: u64,
    expires_at: u64,
    entries: Vec<CatalogEntry>,
    now: SystemTime,
) -> Result<Vec<u8>, RepositoryError> {
    encode_catalog_document_with_withdrawals(issued_at, expires_at, entries, Vec::new(), now)
}

pub fn encode_catalog_document_with_withdrawals(
    issued_at: u64,
    expires_at: u64,
    mut entries: Vec<CatalogEntry>,
    mut withdrawals: Vec<CatalogWithdrawal>,
    now: SystemTime,
) -> Result<Vec<u8>, RepositoryError> {
    entries.sort_by(|left, right| {
        left.plugin_id
            .cmp(&right.plugin_id)
            .then_with(|| left.version.cmp(&right.version))
    });
    withdrawals.sort_by(|left, right| {
        left.plugin_id
            .cmp(&right.plugin_id)
            .then_with(|| left.version.cmp(&right.version))
    });
    let document = CatalogDocument {
        schema_version: 1,
        issued_at,
        expires_at,
        entries,
        withdrawals,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    PluginCatalog::from_unsigned_bytes(&bytes, now)?.ensure_desktop_compatibility_declared()?;
    Ok(bytes)
}

pub async fn fetch_catalog(
    client: &Client,
    catalog_url: &Url,
    signature_url: &Url,
    trust_store: &TrustStore,
    now: SystemTime,
) -> Result<PluginCatalog, RepositoryError> {
    require_https(catalog_url)?;
    require_https(signature_url)?;
    let catalog = fetch_limited(client, catalog_url, MAX_CATALOG_BYTES).await?;
    let signature = fetch_limited(client, signature_url, MAX_CATALOG_BYTES).await?;
    PluginCatalog::from_signed_bytes(&catalog, &signature, trust_store, now)
}

pub async fn download_package(
    client: &Client,
    entry: &CatalogEntry,
    temporary_directory: &Path,
) -> Result<DownloadedPackage, RepositoryError> {
    validate_entry(entry)?;
    std::fs::create_dir_all(temporary_directory).map_err(|source| RepositoryError::Io {
        path: temporary_directory.to_path_buf(),
        source,
    })?;
    let file = TempBuilder::new()
        .prefix(".plugin-download-")
        .suffix(".ssdev-plugin")
        .tempfile_in(temporary_directory)
        .map_err(|source| RepositoryError::Io {
            path: temporary_directory.to_path_buf(),
            source,
        })?;
    let write_handle = file.reopen().map_err(|source| RepositoryError::Io {
        path: file.path().to_path_buf(),
        source,
    })?;
    let mut output = tokio::fs::File::from_std(write_handle);
    let mut response = client
        .get(entry.url.clone())
        .send()
        .await?
        .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size != entry.size)
    {
        return Err(RepositoryError::Invalid(format!(
            "package Content-Length does not match signed size {}",
            entry.size
        )));
    }
    let mut actual_size = 0_u64;
    let mut hasher = Sha256::new();
    while let Some(chunk) = response.chunk().await? {
        actual_size = actual_size.saturating_add(chunk.len() as u64);
        if actual_size > entry.size || actual_size > MAX_PACKAGE_BYTES {
            return Err(RepositoryError::Invalid(
                "download exceeds signed package size or safety limit".into(),
            ));
        }
        hasher.update(&chunk);
        output
            .write_all(&chunk)
            .await
            .map_err(|source| RepositoryError::Io {
                path: file.path().to_path_buf(),
                source,
            })?;
    }
    output
        .sync_all()
        .await
        .map_err(|source| RepositoryError::Io {
            path: file.path().to_path_buf(),
            source,
        })?;
    if actual_size != entry.size {
        return Err(RepositoryError::Invalid(format!(
            "downloaded {actual_size} bytes, expected {}",
            entry.size
        )));
    }
    let actual_sha256 = format!("{:x}", hasher.finalize());
    if actual_sha256 != entry.sha256 {
        return Err(RepositoryError::Invalid(
            "downloaded package SHA-256 does not match signed catalog".into(),
        ));
    }
    Ok(DownloadedPackage {
        file,
        entry: entry.clone(),
    })
}

pub fn secure_http_client() -> Result<Client, RepositoryError> {
    Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(10 * 60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(Into::into)
}

async fn fetch_limited(
    client: &Client,
    url: &Url,
    limit: usize,
) -> Result<Vec<u8>, RepositoryError> {
    let mut response = client.get(url.clone()).send().await?.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(RepositoryError::Invalid(format!(
            "response from {url} exceeds {limit} bytes"
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(RepositoryError::Invalid(format!(
                "response from {url} exceeds {limit} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_entry(entry: &CatalogEntry) -> Result<(), RepositoryError> {
    validate_plugin_id(&entry.plugin_id)?;
    if entry
        .desktop_version_requirement
        .as_ref()
        .is_some_and(|requirement| requirement.to_string().len() > 128)
    {
        return Err(RepositoryError::Invalid(
            "catalog desktop version requirement exceeds 128 characters".into(),
        ));
    }
    require_https(&entry.url)?;
    if entry.url.username() != ""
        || entry.url.password().is_some()
        || entry.url.fragment().is_some()
    {
        return Err(RepositoryError::Invalid(
            "package URL must not contain credentials or fragments".into(),
        ));
    }
    if entry.size == 0 || entry.size > MAX_PACKAGE_BYTES {
        return Err(RepositoryError::Invalid(format!(
            "package size must be 1 to {MAX_PACKAGE_BYTES} bytes"
        )));
    }
    if entry.sha256.len() != 64
        || !entry
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RepositoryError::Invalid(
            "package SHA-256 must be lowercase hexadecimal".into(),
        ));
    }
    Ok(())
}

fn validate_withdrawal(withdrawal: &CatalogWithdrawal) -> Result<(), RepositoryError> {
    validate_plugin_id(&withdrawal.plugin_id)
}

fn validate_plugin_id(plugin_id: &str) -> Result<(), RepositoryError> {
    webplus_plugin_config::validate_portable_plugin_id(plugin_id).map_err(|_| {
        RepositoryError::Invalid(format!(
            "catalog plugin ID [{}] is not Windows-portable",
            plugin_id
        ))
    })
}

fn require_https(url: &Url) -> Result<(), RepositoryError> {
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(RepositoryError::Invalid(format!(
            "repository URL must use HTTPS: {url}"
        )));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogDocument {
    schema_version: u8,
    issued_at: u64,
    expires_at: u64,
    entries: Vec<CatalogEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    withdrawals: Vec<CatalogWithdrawal>,
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("plugin repository data is invalid: {0}")]
    Invalid(String),
    #[error("plugin repository trust error: {0}")]
    Trust(#[from] TrustError),
    #[error("plugin repository JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("plugin repository request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("filesystem operation failed at {path:?}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn catalog_rejects_windows_aliased_plugin_ids() {
        assert!(validate_plugin_id("reader-plugin").is_ok());
        for plugin_id in ["reader.", "CON", "com1.device", "读卡器"] {
            assert!(
                validate_plugin_id(plugin_id).is_err(),
                "accepted {plugin_id}"
            );
        }
    }

    fn signed_catalog(expires_at: u64) -> (TrustStore, Vec<u8>, Vec<u8>) {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let trust_path = root.path().join("trust.json");
        fs::write(
            &trust_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "catalog-key",
                    "algorithm": "ed25519",
                    "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["plugin-catalog"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let catalog = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "issuedAt": 1_700_000_000_u64,
            "expiresAt": expires_at,
            "entries": [{
                "pluginId": "reader-plugin",
                "version": "2.1.0",
                "desktopVersionRequirement": ">=0.1.0, <0.2.0",
                "url": "https://plugins.example.test/reader-2.1.0.ssdev-plugin",
                "sha256": "ab".repeat(32),
                "size": 1024
            }, {
                "pluginId": "reader-plugin",
                "version": "2.2.0",
                "desktopVersionRequirement": ">=0.2.0, <0.3.0",
                "url": "https://plugins.example.test/reader-2.2.0.ssdev-plugin",
                "sha256": "cd".repeat(32),
                "size": 2048
            }]
        }))
        .unwrap();
        let signature = signing_key.sign(&signing_payload(&catalog));
        let signature = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "keyId": "catalog-key",
            "algorithm": "ed25519",
            "signature": BASE64.encode(signature.to_bytes())
        }))
        .unwrap();
        (TrustStore::load(&trust_path).unwrap(), catalog, signature)
    }

    #[test]
    fn verifies_catalog_and_selects_latest_semver() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let (trust, catalog, signature) = signed_catalog(1_700_086_400);
        let catalog = PluginCatalog::from_signed_bytes(&catalog, &signature, &trust, now).unwrap();
        assert_eq!(catalog.signing_key_id(), Some("catalog-key"));
        assert_eq!(
            catalog.select("reader-plugin", None).unwrap().version,
            Version::new(2, 2, 0)
        );
        assert_eq!(
            catalog
                .select_compatible("reader-plugin", None, &Version::new(0, 1, 5))
                .unwrap()
                .version,
            Version::new(2, 1, 0)
        );
        assert_eq!(
            catalog
                .select_compatible("reader-plugin", None, &Version::new(0, 2, 1))
                .unwrap()
                .version,
            Version::new(2, 2, 0)
        );
        assert!(catalog
            .select_compatible("reader-plugin", None, &Version::new(1, 0, 0))
            .is_none());
    }

    #[test]
    fn rejects_tampering_expiry_and_non_https_packages() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let (trust, mut catalog, signature) = signed_catalog(1_700_086_400);
        catalog.push(b' ');
        assert!(PluginCatalog::from_signed_bytes(&catalog, &signature, &trust, now).is_err());

        let (trust, catalog, signature) = signed_catalog(1_700_000_050);
        assert!(PluginCatalog::from_signed_bytes(&catalog, &signature, &trust, now).is_err());

        let entry = CatalogEntry {
            plugin_id: "reader".into(),
            version: Version::new(1, 0, 0),
            desktop_version_requirement: Some(VersionReq::STAR),
            url: Url::parse("http://plugins.example.test/reader.zip").unwrap(),
            sha256: "ab".repeat(32),
            size: 10,
        };
        assert!(validate_entry(&entry).is_err());
    }

    #[test]
    fn catalog_encoding_is_canonical_and_rejects_duplicate_versions() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let first = CatalogEntry {
            plugin_id: "zebra-plugin".into(),
            version: Version::new(1, 0, 0),
            desktop_version_requirement: Some(VersionReq::STAR),
            url: Url::parse("https://plugins.example.test/zebra.ssdev-plugin").unwrap(),
            sha256: "ab".repeat(32),
            size: 10,
        };
        let second = CatalogEntry {
            plugin_id: "alpha-plugin".into(),
            version: Version::new(2, 0, 0),
            desktop_version_requirement: Some(VersionReq::STAR),
            url: Url::parse("https://plugins.example.test/alpha.ssdev-plugin").unwrap(),
            sha256: "cd".repeat(32),
            size: 20,
        };
        let forward = encode_catalog_document(
            1_700_000_000,
            1_700_003_600,
            vec![first.clone(), second.clone()],
            now,
        )
        .unwrap();
        let reverse = encode_catalog_document(
            1_700_000_000,
            1_700_003_600,
            vec![second, first.clone()],
            now,
        )
        .unwrap();
        assert_eq!(forward, reverse);
        assert!(encode_catalog_document(
            1_700_000_000,
            1_700_003_600,
            vec![first.clone(), first],
            now,
        )
        .is_err());
    }

    #[test]
    fn catalog_withdrawals_are_canonical_and_cannot_remain_installable() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let entry = CatalogEntry {
            plugin_id: "reader-plugin".into(),
            version: Version::new(2, 0, 0),
            desktop_version_requirement: Some(VersionReq::STAR),
            url: Url::parse("https://plugins.example.test/reader-2.ssdev-plugin").unwrap(),
            sha256: "ab".repeat(32),
            size: 10,
        };
        let security = CatalogWithdrawal {
            plugin_id: "reader-plugin".into(),
            version: Version::new(1, 0, 0),
            reason: CatalogWithdrawalReason::Security,
        };
        let defective = CatalogWithdrawal {
            plugin_id: "printer-plugin".into(),
            version: Version::new(3, 1, 4),
            reason: CatalogWithdrawalReason::Defective,
        };
        let forward = encode_catalog_document_with_withdrawals(
            1_700_000_000,
            1_700_003_600,
            vec![entry.clone()],
            vec![security.clone(), defective.clone()],
            now,
        )
        .unwrap();
        let reverse = encode_catalog_document_with_withdrawals(
            1_700_000_000,
            1_700_003_600,
            vec![entry.clone()],
            vec![defective, security.clone()],
            now,
        )
        .unwrap();
        assert_eq!(forward, reverse);
        let catalog = PluginCatalog::from_unsigned_bytes(&forward, now).unwrap();
        assert_eq!(catalog.withdrawals().len(), 2);
        assert_eq!(
            catalog
                .withdrawal("reader-plugin", &Version::new(1, 0, 0))
                .map(|withdrawal| withdrawal.reason),
            Some(CatalogWithdrawalReason::Security)
        );
        assert!(catalog
            .select("reader-plugin", Some(&Version::new(1, 0, 0)))
            .is_none());

        let overlapping = CatalogWithdrawal {
            plugin_id: entry.plugin_id.clone(),
            version: entry.version.clone(),
            reason: CatalogWithdrawalReason::PublisherWithdrawn,
        };
        assert!(encode_catalog_document_with_withdrawals(
            1_700_000_000,
            1_700_003_600,
            vec![entry],
            vec![overlapping],
            now,
        )
        .is_err());
        assert!(encode_catalog_document_with_withdrawals(
            1_700_000_000,
            1_700_003_600,
            Vec::new(),
            vec![security.clone(), security],
            now,
        )
        .is_err());
    }

    #[test]
    fn legacy_catalogs_remain_inspectable_but_cannot_be_issued_or_selected() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "issuedAt": 1_700_000_000_u64,
            "expiresAt": 1_700_003_600_u64,
            "entries": [{
                "pluginId": "legacy-reader",
                "version": "1.0.0",
                "url": "https://plugins.example.test/legacy-reader.ssdev-plugin",
                "sha256": "ef".repeat(32),
                "size": 10
            }]
        }))
        .unwrap();

        let catalog = PluginCatalog::from_unsigned_bytes(&bytes, now).unwrap();
        assert!(catalog.select("legacy-reader", None).is_some());
        assert!(catalog
            .select_compatible("legacy-reader", None, &Version::new(0, 1, 0))
            .is_none());
        assert!(catalog.ensure_desktop_compatibility_declared().is_err());

        let legacy_entry = catalog.entries()[0].clone();
        assert!(
            encode_catalog_document(1_700_000_000, 1_700_003_600, vec![legacy_entry], now,)
                .is_err()
        );
    }
}
