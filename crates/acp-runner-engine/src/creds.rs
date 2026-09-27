//! Credential store abstraction.
//!
//! The store holds the *material* of enrolled credential profiles (whitelisted files only).
//! The journal holds non-secret profile records and leases. Implementations:
//!
//! * `K8sSecretStore` (crate `acp-runner-k8s`): one Secret per profile in the controller
//!   namespace (never mounted into agent pods directly; per-attempt Secrets are created from
//!   it for the leased profile only).
//! * [`FileCredentialStore`]: a directory (development and tests).
//!
//! A Vault/external-secrets implementation only needs to implement [`CredentialStore`].

use acp_runner_core::credentials::{CredentialBundle, CredentialMetadata, Provider, validate_bundle};
use acp_runner_journal::{Journal, ProfileUpsert};
use async_trait::async_trait;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct StoredProfile {
    pub name: String,
    pub provider: Provider,
    pub max_concurrent_leases: i32,
    pub metadata: CredentialMetadata,
    pub store_ref: String,
    /// Who may lease the profile (default: nobody).
    pub policy: ProfilePolicy,
}

/// Usage policy of a credential profile: which namespaces (`*` = any) and runner classes
/// (empty = any) may lease it. Stored next to the credential (Secret annotations / profile
/// file) and mirrored into the journal. Default deny.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfilePolicy {
    #[serde(default)]
    pub allowed_namespaces: Vec<String>,
    #[serde(default)]
    pub allowed_classes: Vec<String>,
}

impl ProfilePolicy {
    /// Everybody (tests and single-tenant development setups).
    pub fn any() -> Self {
        ProfilePolicy { allowed_namespaces: vec!["*".into()], allowed_classes: vec![] }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredStoreError {
    #[error("credential profile {0:?} not found")]
    NotFound(String),
    #[error("credential store error: {0}")]
    Store(String),
    #[error("invalid credential bundle: {0}")]
    Invalid(String),
    #[error("concurrent modification of profile {0:?}")]
    Conflict(String),
}

#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn list(&self) -> Result<Vec<StoredProfile>, CredStoreError>;
    async fn load(&self, profile: &str) -> Result<(StoredProfile, CredentialBundle), CredStoreError>;
    /// Create or replace a profile (enrollment). The bundle must already be validated.
    async fn save(&self, profile: &StoredProfile, bundle: &CredentialBundle) -> Result<(), CredStoreError>;
    /// Replace one whitelisted file of an existing profile (validated write-back).
    async fn update_file(
        &self,
        profile: &str,
        key: &str,
        bytes: &[u8],
        metadata: &CredentialMetadata,
    ) -> Result<(), CredStoreError>;
    async fn delete(&self, profile: &str) -> Result<(), CredStoreError>;
    /// Replace the usage policy of an existing profile (credential material untouched).
    async fn set_policy(&self, profile: &str, policy: &ProfilePolicy) -> Result<(), CredStoreError>;
}

/// Mirror the store's profiles into `credential_profiles` (non-secret records only).
pub async fn sync_profiles(store: &dyn CredentialStore, journal: &Journal) -> anyhow::Result<usize> {
    let profiles = store.list().await?;
    for p in &profiles {
        let max = if p.provider.spec().exclusive_lease { 1 } else { p.max_concurrent_leases.max(1) };
        journal
            .upsert_profile(&ProfileUpsert {
                name: p.name.clone(),
                provider: p.provider.as_str().to_string(),
                store: p.store_ref.clone(),
                max_concurrent_leases: max,
                metadata: serde_json::to_value(&p.metadata)?,
                material_fingerprint: p.metadata.material_fingerprint.clone(),
                allowed_namespaces: p.policy.allowed_namespaces.clone(),
                allowed_classes: p.policy.allowed_classes.clone(),
            })
            .await?;
    }
    Ok(profiles.len())
}

/// Directory layout: `<root>/<profile>/profile.json` + one file per whitelisted key.
pub struct FileCredentialStore {
    pub root: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileFile {
    provider: Provider,
    max_concurrent_leases: i32,
    metadata: CredentialMetadata,
    #[serde(default)]
    policy: ProfilePolicy,
}

fn valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 50
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

pub fn check_profile_name(name: &str) -> Result<(), CredStoreError> {
    if valid_profile_name(name) {
        Ok(())
    } else {
        Err(CredStoreError::Invalid(format!(
            "profile name {name:?} must be a DNS label (lowercase letters, digits, '-', max 50)"
        )))
    }
}

#[async_trait]
impl CredentialStore for FileCredentialStore {
    async fn list(&self) -> Result<Vec<StoredProfile>, CredStoreError> {
        let mut out = vec![];
        let Ok(rd) = std::fs::read_dir(&self.root) else { return Ok(out) };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Ok(bytes) = std::fs::read(e.path().join("profile.json"))
                && let Ok(pf) = serde_json::from_slice::<ProfileFile>(&bytes)
            {
                out.push(StoredProfile {
                    store_ref: format!("file:{}", e.path().display()),
                    name,
                    provider: pf.provider,
                    max_concurrent_leases: pf.max_concurrent_leases,
                    metadata: pf.metadata,
                    policy: pf.policy,
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn load(&self, profile: &str) -> Result<(StoredProfile, CredentialBundle), CredStoreError> {
        check_profile_name(profile)?;
        let dir = self.root.join(profile);
        let pf: ProfileFile = serde_json::from_slice(
            &std::fs::read(dir.join("profile.json")).map_err(|_| CredStoreError::NotFound(profile.to_string()))?,
        )
        .map_err(|e| CredStoreError::Store(e.to_string()))?;
        let mut bundle = CredentialBundle::new();
        for key in pf.provider.spec().keys() {
            let b = std::fs::read(dir.join(key)).map_err(|e| CredStoreError::Store(format!("{key}: {e}")))?;
            bundle.insert(key.to_string(), b);
        }
        let sp = StoredProfile {
            name: profile.to_string(),
            provider: pf.provider,
            max_concurrent_leases: pf.max_concurrent_leases,
            metadata: pf.metadata,
            store_ref: format!("file:{}", dir.display()),
            policy: pf.policy,
        };
        Ok((sp, bundle))
    }

    async fn save(&self, profile: &StoredProfile, bundle: &CredentialBundle) -> Result<(), CredStoreError> {
        check_profile_name(&profile.name)?;
        validate_bundle(profile.provider, bundle).map_err(|e| CredStoreError::Invalid(e.to_string()))?;
        let dir = self.root.join(&profile.name);
        let io = |e: std::io::Error| CredStoreError::Store(e.to_string());
        std::fs::create_dir_all(&dir).map_err(io)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        for (k, v) in bundle {
            let p = dir.join(k);
            std::fs::write(&p, v).map_err(io)?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        }
        let pf = ProfileFile {
            provider: profile.provider,
            max_concurrent_leases: profile.max_concurrent_leases,
            metadata: profile.metadata.clone(),
            policy: profile.policy.clone(),
        };
        std::fs::write(
            dir.join("profile.json"),
            serde_json::to_vec_pretty(&pf).map_err(|e| CredStoreError::Store(e.to_string()))?,
        )
        .map_err(io)
    }

    async fn update_file(
        &self,
        profile: &str,
        key: &str,
        bytes: &[u8],
        metadata: &CredentialMetadata,
    ) -> Result<(), CredStoreError> {
        let (mut sp, mut bundle) = self.load(profile).await?;
        if !bundle.contains_key(key) {
            return Err(CredStoreError::Invalid(format!("key {key:?} not in profile")));
        }
        bundle.insert(key.to_string(), bytes.to_vec());
        sp.metadata = metadata.clone();
        self.save(&sp, &bundle).await
    }

    async fn delete(&self, profile: &str) -> Result<(), CredStoreError> {
        check_profile_name(profile)?;
        std::fs::remove_dir_all(self.root.join(profile)).map_err(|e| CredStoreError::Store(e.to_string()))
    }

    async fn set_policy(&self, profile: &str, policy: &ProfilePolicy) -> Result<(), CredStoreError> {
        let (mut sp, bundle) = self.load(profile).await?;
        sp.policy = policy.clone();
        self.save(&sp, &bundle).await
    }
}
