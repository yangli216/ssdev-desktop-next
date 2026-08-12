use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssdev_config::{parse_website, DesktopConfig};
use thiserror::Error;
use url::Url;
use webplus_plugin_trust::{DetachedSignatureDocument, TrustError, TrustPurpose, TrustStore};

const MAX_POLICY_BYTES: u64 = 256 * 1024;
const MAX_ORIGINS_PER_CLASS: usize = 128;
const MAX_SERVICES_PER_ORIGIN: usize = 256;
const MAX_METHODS_PER_SERVICE: usize = 256;
const MAX_ROUTING_FIELD_CHARS: usize = 256;
const ORIGIN_POLICY_DOMAIN: &[u8] = b"SSDEV-ORIGIN-POLICY\0";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyDocument {
    schema_version: u8,
    business_grants: Vec<BusinessGrantDocument>,
    #[serde(default)]
    navigation_origins: Vec<String>,
    #[serde(default)]
    external_origins: Vec<String>,
    #[serde(default)]
    allow_insecure_http: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyHeader {
    schema_version: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BusinessGrantDocument {
    origin: String,
    services: Vec<ServiceGrantDocument>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceGrantDocument {
    service_id: String,
    methods: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OriginPolicy {
    business_grants: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    navigation_origins: BTreeSet<String>,
    external_origins: BTreeSet<String>,
    allow_insecure_http: bool,
    enforced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginPolicySummary {
    pub enforced: bool,
    pub business_origins: usize,
    pub service_grants: usize,
    pub method_grants: usize,
    pub navigation_origins: usize,
    pub external_origins: usize,
    pub allow_insecure_http: bool,
}

impl OriginPolicy {
    pub fn load(
        policy_path: &Path,
        signature_path: &Path,
        trust_store: &TrustStore,
    ) -> Result<Self, OriginPolicyError> {
        let bytes = read_limited(policy_path)?;
        let signature_bytes = read_limited(signature_path)?;
        let signature: DetachedSignatureDocument = serde_json::from_slice(&signature_bytes)
            .map_err(|source| OriginPolicyError::Json {
                path: signature_path.to_path_buf(),
                source,
            })?;
        signature.validate()?;
        trust_store.verify_detached(
            TrustPurpose::OriginPolicy,
            &signature.key_id,
            &signing_payload(&bytes),
            &signature.signature,
        )?;

        Self::from_unsigned_bytes_at(&bytes, policy_path)
    }

    /// Validates an unsigned policy before it is sent to an external signer.
    pub fn from_unsigned_bytes(bytes: &[u8]) -> Result<Self, OriginPolicyError> {
        Self::from_unsigned_bytes_at(bytes, Path::new("origin-policy.json"))
    }

    /// Explicit development escape hatch. Release builds never select this mode.
    pub fn development_unrestricted() -> Self {
        Self {
            business_grants: BTreeMap::new(),
            navigation_origins: BTreeSet::new(),
            external_origins: BTreeSet::new(),
            allow_insecure_http: true,
            enforced: false,
        }
    }

    pub fn authorize(&self, config: &DesktopConfig) -> Result<(), OriginPolicyError> {
        config
            .validate()
            .map_err(|error| OriginPolicyError::Invalid(error.to_string()))?;
        if !self.enforced {
            return Ok(());
        }

        for origin in config
            .business_origins()
            .map_err(|error| OriginPolicyError::Invalid(error.to_string()))?
        {
            self.require_business_origin(&origin)?;
        }
        for origin in normalized_config_origins(&config.trusted_origins)? {
            if !self.business_grants.contains_key(&origin)
                && !self.navigation_origins.contains(&origin)
            {
                return Err(OriginPolicyError::Unauthorized {
                    class: "navigation",
                    origin,
                });
            }
        }
        for origin in normalized_config_origins(&config.external_origins)? {
            if !self.business_grants.contains_key(&origin)
                && !self.external_origins.contains(&origin)
            {
                return Err(OriginPolicyError::Unauthorized {
                    class: "external",
                    origin,
                });
            }
        }
        Ok(())
    }

    pub fn authorize_plugin_invocation(
        &self,
        origin: &str,
        service_id: &str,
        method: &str,
    ) -> Result<(), OriginPolicyError> {
        if !self.enforced {
            return Ok(());
        }
        validate_routing_field(service_id, "serviceId")?;
        validate_routing_field(method, "method")?;
        let services =
            self.business_grants
                .get(origin)
                .ok_or_else(|| OriginPolicyError::Unauthorized {
                    class: "business",
                    origin: origin.to_owned(),
                })?;
        let methods =
            services
                .get(service_id)
                .ok_or_else(|| OriginPolicyError::UnauthorizedService {
                    origin: origin.to_owned(),
                    service_id: service_id.to_owned(),
                })?;
        if methods.contains(method) {
            Ok(())
        } else {
            Err(OriginPolicyError::UnauthorizedMethod {
                origin: origin.to_owned(),
                service_id: service_id.to_owned(),
                method: method.to_owned(),
            })
        }
    }

    pub fn summary(&self) -> OriginPolicySummary {
        OriginPolicySummary {
            enforced: self.enforced,
            business_origins: self.business_grants.len(),
            service_grants: self.business_grants.values().map(BTreeMap::len).sum(),
            method_grants: self
                .business_grants
                .values()
                .flat_map(BTreeMap::values)
                .map(BTreeSet::len)
                .sum(),
            navigation_origins: self.navigation_origins.len(),
            external_origins: self.external_origins.len(),
            allow_insecure_http: self.allow_insecure_http,
        }
    }

    fn from_document(document: PolicyDocument, enforced: bool) -> Result<Self, OriginPolicyError> {
        if document.schema_version != 2 {
            return Err(OriginPolicyError::Invalid(format!(
                "unsupported origin policy schema [{}]",
                document.schema_version
            )));
        }
        if document.business_grants.is_empty() {
            return Err(OriginPolicyError::Invalid(
                "origin policy must contain at least one scoped business grant".into(),
            ));
        }
        let business_grants =
            normalize_business_grants(document.business_grants, document.allow_insecure_http)?;
        let navigation_origins = normalize_policy_origins(
            document.navigation_origins,
            document.allow_insecure_http,
            "navigation",
        )?;
        let external_origins = normalize_policy_origins(
            document.external_origins,
            document.allow_insecure_http,
            "external",
        )?;
        Ok(Self {
            business_grants,
            navigation_origins,
            external_origins,
            allow_insecure_http: document.allow_insecure_http,
            enforced,
        })
    }

    fn from_unsigned_bytes_at(bytes: &[u8], path: &Path) -> Result<Self, OriginPolicyError> {
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return Err(OriginPolicyError::Invalid(format!(
                "origin policy exceeds {MAX_POLICY_BYTES} bytes"
            )));
        }
        let header: PolicyHeader =
            serde_json::from_slice(bytes).map_err(|source| OriginPolicyError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        if header.schema_version != 2 {
            return Err(OriginPolicyError::Invalid(format!(
                "unsupported origin policy schema [{}]; schema 2 scoped grants are required",
                header.schema_version
            )));
        }
        let document: PolicyDocument =
            serde_json::from_slice(bytes).map_err(|source| OriginPolicyError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        Self::from_document(document, true)
    }

    fn require_business_origin(&self, origin: &str) -> Result<(), OriginPolicyError> {
        if !self.business_grants.contains_key(origin) {
            return Err(OriginPolicyError::Unauthorized {
                class: "business",
                origin: origin.to_owned(),
            });
        }
        if origin.starts_with("http://") && !self.allow_insecure_http {
            return Err(OriginPolicyError::Invalid(format!(
                "insecure origin [{origin}] is disabled by policy"
            )));
        }
        Ok(())
    }
}

pub fn signing_payload(policy_bytes: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(policy_bytes);
    let mut payload = Vec::with_capacity(ORIGIN_POLICY_DOMAIN.len() + digest.len());
    payload.extend_from_slice(ORIGIN_POLICY_DOMAIN);
    payload.extend_from_slice(&digest);
    payload
}

fn normalized_config_origins(values: &[String]) -> Result<BTreeSet<String>, OriginPolicyError> {
    values
        .iter()
        .map(|value| {
            parse_website(value)
                .map(|url| url.origin().ascii_serialization())
                .map_err(|error| OriginPolicyError::Invalid(error.to_string()))
        })
        .collect()
}

fn normalize_business_grants(
    grants: Vec<BusinessGrantDocument>,
    allow_insecure_http: bool,
) -> Result<BTreeMap<String, BTreeMap<String, BTreeSet<String>>>, OriginPolicyError> {
    if grants.len() > MAX_ORIGINS_PER_CLASS {
        return Err(OriginPolicyError::Invalid(format!(
            "origin policy contains more than {MAX_ORIGINS_PER_CLASS} business origins"
        )));
    }
    let mut normalized = BTreeMap::new();
    for grant in grants {
        let origin = normalize_policy_origin(&grant.origin, allow_insecure_http, "business")?;
        if grant.services.is_empty() || grant.services.len() > MAX_SERVICES_PER_ORIGIN {
            return Err(OriginPolicyError::Invalid(format!(
                "business origin [{origin}] must authorize between 1 and {MAX_SERVICES_PER_ORIGIN} services"
            )));
        }
        let mut services = BTreeMap::new();
        for service in grant.services {
            validate_routing_field(&service.service_id, "serviceId")?;
            if service.methods.is_empty() || service.methods.len() > MAX_METHODS_PER_SERVICE {
                return Err(OriginPolicyError::Invalid(format!(
                    "service [{}] for business origin [{origin}] must authorize between 1 and {MAX_METHODS_PER_SERVICE} methods",
                    service.service_id
                )));
            }
            let mut methods = BTreeSet::new();
            for method in service.methods {
                validate_routing_field(&method, "method")?;
                if !methods.insert(method.clone()) {
                    return Err(OriginPolicyError::Invalid(format!(
                        "duplicate method [{method}] for service [{}] and business origin [{origin}]",
                        service.service_id
                    )));
                }
            }
            if services
                .insert(service.service_id.clone(), methods)
                .is_some()
            {
                return Err(OriginPolicyError::Invalid(format!(
                    "duplicate service [{}] for business origin [{origin}]",
                    service.service_id
                )));
            }
        }
        if normalized.insert(origin.clone(), services).is_some() {
            return Err(OriginPolicyError::Invalid(format!(
                "duplicate business origin [{origin}]"
            )));
        }
    }
    Ok(normalized)
}

fn validate_routing_field(value: &str, label: &str) -> Result<(), OriginPolicyError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_ROUTING_FIELD_CHARS
        || value == "*"
    {
        return Err(OriginPolicyError::Invalid(format!(
            "{label} must be a non-empty exact name of at most {MAX_ROUTING_FIELD_CHARS} characters without surrounding whitespace or wildcards"
        )));
    }
    Ok(())
}

fn normalize_policy_origins(
    values: Vec<String>,
    allow_insecure_http: bool,
    class: &'static str,
) -> Result<BTreeSet<String>, OriginPolicyError> {
    if values.len() > MAX_ORIGINS_PER_CLASS {
        return Err(OriginPolicyError::Invalid(format!(
            "origin policy contains more than {MAX_ORIGINS_PER_CLASS} {class} origins"
        )));
    }
    let mut origins = BTreeSet::new();
    for value in values {
        let origin = normalize_policy_origin(&value, allow_insecure_http, class)?;
        if !origins.insert(origin.clone()) {
            return Err(OriginPolicyError::Invalid(format!(
                "duplicate {class} origin [{origin}]"
            )));
        }
    }
    Ok(origins)
}

fn normalize_policy_origin(
    value: &str,
    allow_insecure_http: bool,
    class: &'static str,
) -> Result<String, OriginPolicyError> {
    let url = Url::parse(value).map_err(|error| {
        OriginPolicyError::Invalid(format!("invalid {class} origin [{value}]: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OriginPolicyError::Invalid(format!(
            "{class} origin [{value}] must be a bare HTTP(S) origin without credentials, path, query, or fragment"
        )));
    }
    if url.scheme() == "http" && !allow_insecure_http {
        return Err(OriginPolicyError::Invalid(format!(
            "{class} origin [{value}] uses HTTP but allowInsecureHttp is false"
        )));
    }
    Ok(url.origin().ascii_serialization())
}

fn read_limited(path: &Path) -> Result<Vec<u8>, OriginPolicyError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| OriginPolicyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES {
        return Err(OriginPolicyError::Invalid(format!(
            "origin policy file [{}] must be regular and no larger than {MAX_POLICY_BYTES} bytes",
            path.display()
        )));
    }
    fs::read(path).map_err(|source| OriginPolicyError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum OriginPolicyError {
    #[error("failed to read origin policy [{path}]: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid origin policy JSON [{path}]: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("origin policy trust verification failed: {0}")]
    Trust(#[from] TrustError),
    #[error("invalid origin policy: {0}")]
    Invalid(String),
    #[error("{class} origin [{origin}] is not authorized by the signed deployment policy")]
    Unauthorized { class: &'static str, origin: String },
    #[error("service [{service_id}] is not authorized for business origin [{origin}]")]
    UnauthorizedService { origin: String, service_id: String },
    #[error("method [{method}] of service [{service_id}] is not authorized for business origin [{origin}]")]
    UnauthorizedMethod {
        origin: String,
        service_id: String,
        method: String,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn load_signed(document: serde_json::Value) -> Result<OriginPolicy, OriginPolicyError> {
        let root = tempdir().unwrap();
        let policy_path = root.path().join("origin-policy.json");
        let signature_path = root.path().join("origin-policy.sig.json");
        let trust_path = root.path().join("plugin-trust.json");
        let bytes = serde_json::to_vec_pretty(&document).unwrap();
        fs::write(&policy_path, &bytes).unwrap();

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signature = signing_key.sign(&signing_payload(&bytes));
        fs::write(
            &signature_path,
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": 1,
                "keyId": "test-key",
                "algorithm": "ed25519",
                "signature": STANDARD.encode(signature.to_bytes())
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &trust_path,
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "test-key",
                    "algorithm": "ed25519",
                    "publicKey": STANDARD.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["origin-policy"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let trust = TrustStore::load(&trust_path).unwrap();
        OriginPolicy::load(&policy_path, &signature_path, &trust)
    }

    fn policy_document() -> serde_json::Value {
        json!({
            "schemaVersion": 2,
            "businessGrants": [{
                "origin": "https://business.example.test",
                "services": [
                    {"serviceId": "reader", "methods": ["read", "reset"]},
                    {"serviceId": "printer", "methods": ["print"]}
                ]
            }],
            "navigationOrigins": ["https://sso.example.test"],
            "externalOrigins": ["https://help.example.test"],
            "allowInsecureHttp": false
        })
    }

    #[test]
    fn signed_policy_authorizes_only_declared_origin_classes() {
        let policy = load_signed(policy_document()).unwrap();
        let allowed = DesktopConfig {
            website: Some("https://business.example.test/app".into()),
            trusted_origins: vec!["https://sso.example.test/login".into()],
            external_origins: vec!["https://help.example.test/docs".into()],
            ..DesktopConfig::default()
        };
        policy.authorize(&allowed).unwrap();
        policy
            .authorize_plugin_invocation("https://business.example.test", "reader", "read")
            .unwrap();
        assert!(matches!(
            policy.authorize_plugin_invocation("https://business.example.test", "reader", "delete"),
            Err(OriginPolicyError::UnauthorizedMethod { .. })
        ));
        assert!(matches!(
            policy.authorize_plugin_invocation("https://business.example.test", "admin", "reset"),
            Err(OriginPolicyError::UnauthorizedService { .. })
        ));
        assert!(matches!(
            policy.authorize_plugin_invocation("https://sso.example.test", "reader", "read"),
            Err(OriginPolicyError::Unauthorized { .. })
        ));
        assert_eq!(policy.summary().business_origins, 1);
        assert_eq!(policy.summary().service_grants, 2);
        assert_eq!(policy.summary().method_grants, 3);

        let unauthorized = DesktopConfig {
            website: Some("https://attacker.example.test".into()),
            ..DesktopConfig::default()
        };
        assert!(matches!(
            policy.authorize(&unauthorized),
            Err(OriginPolicyError::Unauthorized {
                class: "business",
                ..
            })
        ));
    }

    #[test]
    fn http_requires_an_explicit_signed_policy_exception() {
        let mut denied = policy_document();
        denied["businessGrants"][0]["origin"] = json!("http://legacy.example.test");
        assert!(load_signed(denied).is_err());

        let allowed = json!({
            "schemaVersion": 2,
            "businessGrants": [{
                "origin": "http://legacy.example.test",
                "services": [{"serviceId": "reader", "methods": ["read"]}]
            }],
            "allowInsecureHttp": true
        });
        let policy = load_signed(allowed).unwrap();
        policy
            .authorize(&DesktopConfig {
                website: Some("http://legacy.example.test/app".into()),
                ..DesktopConfig::default()
            })
            .unwrap();
    }

    #[test]
    fn tampering_and_non_origin_urls_are_rejected() {
        let mut invalid = policy_document();
        invalid["businessGrants"][0]["origin"] = json!("https://business.example.test/path");
        assert!(load_signed(invalid).is_err());

        let mut duplicate = policy_document();
        duplicate["businessGrants"] = json!([
            {
                "origin": "https://business.example.test",
                "services": [{"serviceId": "reader", "methods": ["read"]}]
            },
            {
                "origin": "https://business.example.test/",
                "services": [{"serviceId": "printer", "methods": ["print"]}]
            }
        ]);
        assert!(load_signed(duplicate).is_err());
    }

    #[test]
    fn rejects_legacy_unscoped_wildcard_and_duplicate_grants() {
        let legacy = json!({
            "schemaVersion": 1,
            "businessOrigins": ["https://business.example.test"],
            "allowInsecureHttp": false
        });
        assert!(load_signed(legacy)
            .unwrap_err()
            .to_string()
            .contains("schema 2 scoped grants are required"));

        for invalid in [
            json!({
                "schemaVersion": 2,
                "businessGrants": [{
                    "origin": "https://business.example.test",
                    "services": [{"serviceId": "*", "methods": ["read"]}]
                }],
                "allowInsecureHttp": false
            }),
            json!({
                "schemaVersion": 2,
                "businessGrants": [{
                    "origin": "https://business.example.test",
                    "services": [{"serviceId": "reader", "methods": ["*"]}]
                }],
                "allowInsecureHttp": false
            }),
            json!({
                "schemaVersion": 2,
                "businessGrants": [{
                    "origin": "https://business.example.test",
                    "services": [
                        {"serviceId": "reader", "methods": ["read"]},
                        {"serviceId": "reader", "methods": ["reset"]}
                    ]
                }],
                "allowInsecureHttp": false
            }),
            json!({
                "schemaVersion": 2,
                "businessGrants": [{
                    "origin": "https://business.example.test",
                    "services": [{"serviceId": "reader", "methods": ["read", "read"]}]
                }],
                "allowInsecureHttp": false
            }),
        ] {
            assert!(load_signed(invalid).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn policy_reader_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let target = root.path().join("target.json");
        let link = root.path().join("origin-policy.json");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_limited(&link).is_err());
    }
}
