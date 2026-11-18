use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, de::{Error as _, MapAccess, Visitor}};

use crate::security::{fingerprint, storage, valid_fingerprint};

const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_DESKTOPS: usize = 4096;
const MAX_PATTERNS: usize = 64;

pub const TOOLS: &[&str] = &[
    "sap_abap_docu", "sap_activate", "sap_atc_run", "sap_create_object", "sap_get_source",
    "sap_inactive_objects", "sap_lock", "sap_object_structure", "sap_run_unit_test",
    "sap_search_object", "sap_set_source", "sap_sql_query", "sap_syntax_check", "sap_unlock",
    "sap_usage_references",
];

// A reference search posts to a fixed where-used endpoint. The other
// observational tools use GET. SQL, test and check runs require opt-in.
fn observational(tool: &str) -> bool {
    matches!(tool, "sap_abap_docu" | "sap_get_source" | "sap_inactive_objects"
        | "sap_object_structure" | "sap_search_object" | "sap_usage_references")
}

fn package_aware(tool: &str) -> bool {
    matches!(tool, "sap_activate" | "sap_create_object" | "sap_get_source" | "sap_lock"
        | "sap_object_structure" | "sap_search_object" | "sap_set_source" | "sap_unlock")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub(crate) read_only: bool,
    // Explicit null is unrestricted. Missing fields in a damaged file must
    // never silently remove a previously configured restriction.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) actions: Option<Vec<String>>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) packages: Option<Vec<String>>,
}

impl Rules {
    pub(crate) const fn desktop_default() -> Self {
        Self { read_only: true, actions: None, packages: None }
    }

    fn normalize(&mut self) -> Result<()> {
        if let Some(actions) = &mut self.actions {
            ensure!(actions.len() <= TOOLS.len(), "Too many tool names.");
            for action in actions.iter() {
                ensure!(TOOLS.contains(&action.as_str()), "Unrecognized tool name.");
            }
            actions.sort_unstable();
            actions.dedup();
        }
        if let Some(packages) = &mut self.packages {
            ensure!(packages.len() <= MAX_PATTERNS, "Each scope supports up to {MAX_PATTERNS} package patterns.");
            for pattern in packages.iter_mut() {
                pattern.make_ascii_uppercase();
                ensure!(valid_pattern(pattern), "Invalid SAP package pattern.");
            }
            packages.sort_unstable();
            packages.dedup();
        }
        Ok(())
    }

    fn permits(&self, tool: &str) -> bool {
        (!self.read_only || observational(tool))
            && self.actions.as_ref().is_none_or(|names| names.iter().any(|name| name == tool))
            && self.packages.as_ref().is_none_or(|patterns| !patterns.is_empty() && package_aware(tool))
    }
}

fn valid_pattern(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let literal = pattern.strip_suffix('*').unwrap_or(pattern);
    if literal.is_empty() || literal.len() > 30 {
        return false;
    }
    let name = if let Some(namespaced) = literal.strip_prefix('/') {
        let Some((namespace, name)) = namespaced.split_once('/') else { return false };
        if namespace.is_empty() || !namespace.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_') {
            return false;
        }
        if name.is_empty() {
            return pattern.ends_with('*');
        }
        name
    } else {
        literal
    };
    name.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || matches!(c, b'_' | b'$'))
}

fn desktops<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error> {
    struct Desktops<T>(PhantomData<fn() -> T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Desktops<T> {
        type Value = BTreeMap<String, T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("entries keyed by unique desktop certificate fingerprints")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((pin, entry)) = map.next_entry::<String, T>()? {
                if result.len() >= MAX_DESKTOPS || !valid_fingerprint(&pin) || result.insert(pin, entry).is_some() {
                    return Err(A::Error::custom("Invalid or duplicate desktop fingerprint, or too many desktops."));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Desktops(PhantomData))
}

fn normalize_endpoints(desktop: &str, endpoints: &mut [String]) -> Result<()> {
    ensure!(endpoints.iter().all(|id| valid_fingerprint(id) && id != desktop), "Invalid Eclipse endpoint fingerprint.");
    endpoints.sort_unstable();
    ensure!(endpoints.windows(2).all(|pair| pair[0] != pair[1]), "Duplicate Eclipse endpoint fingerprint.");
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    // Hash of the exact file read by the editor. Never trust a revision
    // string inside the document to detect an intervening edit.
    #[serde(skip)]
    pub(crate) revision: String,
    pub(crate) global: Rules,
    #[serde(deserialize_with = "desktops")]
    pub(crate) desktops: BTreeMap<String, Rules>,
    // Earlier documents had no assignments. Migration starts with access to zero endpoints.
    #[serde(default, deserialize_with = "desktops")]
    pub(crate) endpoint_grants: BTreeMap<String, Vec<String>>,
}

impl Default for Document {
    fn default() -> Self {
        Self {
            revision: String::new(),
            global: Rules { read_only: false, actions: None, packages: None },
            desktops: BTreeMap::new(),
            endpoint_grants: BTreeMap::new(),
        }
    }
}

impl Document {
    fn effective(mut self, desktop: &str) -> Effective {
        let rules = self.desktops.remove(desktop).unwrap_or_else(Rules::desktop_default);
        let permits = |tool: &str| self.global.permits(tool) && rules.permits(tool);
        // Source writes can lock, activate and unlock regardless of the caller's options.
        let source_dependencies = ["sap_lock", "sap_unlock", "sap_activate"].into_iter().all(permits);
        let actions = TOOLS.iter().copied().filter(|tool|
            permits(tool) && (*tool != "sap_set_source" || source_dependencies)
        ).collect();
        let package_scopes = [self.global.packages, rules.packages].into_iter().flatten().collect();
        Effective { actions, package_scopes }
    }
}

pub struct Effective {
    actions: Vec<&'static str>,
    package_scopes: Vec<Vec<String>>,
}

impl Effective {
    pub(crate) fn allows(&self, tool: &str) -> bool {
        self.actions.contains(&tool)
    }

    pub(crate) const fn package_scopes(&self) -> &[Vec<String>] {
        self.package_scopes.as_slice()
    }
}

pub struct PolicyStore {
    dir: PathBuf,
}

impl PolicyStore {
    pub(crate) fn load(dir: &Path) -> Result<Self> {
        let store = Self { dir: dir.to_path_buf() };
        let lock_path = dir.join("policy.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut lock = options.open(&lock_path).context("Opening the policy lock in the PKI directory")?;
        lock.lock().context("Locking the policy store")?;
        // Keep the marker in the locked inode. A failed first initialization
        // can retry; deleting policy.json after initialization fails closed.
        let mut marker = [0_u8; 2];
        let length = lock.read(&mut marker)?;
        ensure!(length == 0 || (length == 1 && marker[0] == b'1'), "Invalid policy store marker.");
        let path = store.path();
        if length == 0 && !path.try_exists()? {
            let bytes = serde_json::to_vec_pretty(&Document::default())?;
            storage::write_new(&path, &bytes)?;
        }
        store.snapshot()?;
        if length == 0 {
            lock.write_all(b"1")?;
            lock.sync_all()?;
            #[cfg(unix)]
            store.sync_directory()?;
        }
        drop(lock);
        Ok(store)
    }

    fn path(&self) -> PathBuf {
        self.dir.join("policy.json")
    }

    #[cfg(unix)]
    fn sync_directory(&self) -> Result<()> {
        File::open(&self.dir)?.sync_all().context("Synchronizing the policy directory")
    }

    pub(crate) fn snapshot(&self) -> Result<Document> {
        let mut bytes = Vec::new();
        let path = self.path();
        ensure!(fs::symlink_metadata(&path).context("Inspecting policy.json")?.is_file(), "Expected a regular policy file.");
        File::open(&path).context("Opening policy.json")?
            .take(MAX_FILE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_FILE_BYTES, "Policy file exceeds the size limit.");
        let mut document: Document = serde_json::from_slice(&bytes).context("Parsing policy.json")?;
        document.global.normalize()?;
        for rules in document.desktops.values_mut() {
            rules.normalize()?;
        }
        for (desktop, endpoints) in &mut document.endpoint_grants {
            normalize_endpoints(desktop, endpoints)?;
        }
        document.revision = hex::encode(fingerprint(&bytes));
        Ok(document)
    }

    #[cfg(test)]
    fn effective(&self, fingerprint: &[u8; 32]) -> Result<Effective> {
        Ok(self.snapshot()?.effective(&hex::encode(fingerprint)))
    }

    pub(crate) fn effective_for_endpoint(&self, desktop: &[u8; 32], endpoint: &str) -> Result<Option<Effective>> {
        let document = self.snapshot()?;
        let pin = hex::encode(desktop);
        let granted = document.endpoint_grants.get(&pin)
            .is_some_and(|ids| ids.binary_search_by(|id| id.as_str().cmp(endpoint)).is_ok());
        Ok(granted.then(|| document.effective(&pin)))
    }

    pub(crate) fn set_global(&self, revision: &str, mut rules: Rules) -> Result<()> {
        rules.normalize()?;
        self.update(revision, |document| {
            document.global = rules;
            Ok(())
        })
    }

    pub(crate) fn endpoint_grants(&self, desktop: &[u8; 32]) -> Result<Vec<String>> {
        Ok(self.snapshot()?.endpoint_grants.remove(&hex::encode(desktop)).unwrap_or_default())
    }

    pub(crate) fn set_endpoint_grants(&self, revision: &str, desktop: &str, mut endpoints: Vec<String>) -> Result<()> {
        ensure!(valid_fingerprint(desktop), "Invalid desktop fingerprint.");
        normalize_endpoints(desktop, &mut endpoints)?;
        self.update(revision, |document| {
            if endpoints.is_empty() {
                document.endpoint_grants.remove(desktop);
            } else {
                ensure!(document.endpoint_grants.contains_key(desktop) || document.endpoint_grants.len() < MAX_DESKTOPS,
                    "Too many desktops with endpoint assignments.");
                document.endpoint_grants.insert(desktop.to_owned(), endpoints);
            }
            Ok(())
        })
    }

    pub(crate) fn set_desktop(&self, revision: &str, fingerprint: &str, rules: Option<Rules>) -> Result<()> {
        ensure!(valid_fingerprint(fingerprint), "Invalid desktop fingerprint.");
        self.update(revision, |document| {
            if let Some(mut rules) = rules {
                rules.normalize()?;
                ensure!(document.desktops.contains_key(fingerprint) || document.desktops.len() < MAX_DESKTOPS, "Too many desktop overrides.");
                document.desktops.insert(fingerprint.to_owned(), rules);
            } else {
                document.desktops.remove(fingerprint);
            }
            Ok(())
        })
    }

    fn update(&self, revision: &str, edit: impl FnOnce(&mut Document) -> Result<()>) -> Result<()> {
        let lock = OpenOptions::new().read(true).write(true).open(self.dir.join("policy.lock"))?;
        lock.lock().context("Locking the policy store")?;
        let mut document = self.snapshot()?;
        ensure!(document.revision == revision, "Policy changed since it was opened. Reload it before saving.");
        edit(&mut document)?;
        let bytes = serde_json::to_vec_pretty(&document)?;
        ensure!(bytes.len() <= MAX_FILE_BYTES, "Policy file exceeds the size limit.");
        let path = self.path();
        storage::stage(&path, &bytes)?.persist(&path)?.sync_all()?;
        #[cfg(unix)]
        self.sync_directory()?;
        drop(lock);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn unrestricted() -> Rules {
        Rules { read_only: false, actions: None, packages: None }
    }

    #[test]
    fn defaults_and_overrides_apply_at_both_levels() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::load(dir.path()).unwrap();
        let desktop = [1; 32];
        let initial = store.effective(&desktop).unwrap();
        assert!(initial.allows("sap_usage_references"));
        for tool in ["sap_lock", "sap_set_source", "sap_activate", "sap_sql_query", "sap_run_unit_test", "unknown"] {
            assert!(!initial.allows(tool));
        }
        store.set_desktop(&store.snapshot().unwrap().revision, &hex::encode(desktop), Some(unrestricted())).unwrap();
        let expanded = store.effective(&desktop).unwrap();
        assert!(TOOLS.iter().all(|tool| expanded.allows(tool)));
        assert!(!expanded.allows("sap_new_method"));
        assert!(!store.effective(&[2; 32]).unwrap().allows("sap_set_source"));
        store.set_global(&store.snapshot().unwrap().revision, Rules {
            actions: Some(vec!["sap_set_source".into(), "sap_get_source".into()]), ..Rules::desktop_default()
        }).unwrap();
        let limited = store.effective(&desktop).unwrap();
        assert!(limited.allows("sap_get_source"));
        assert!(!limited.allows("sap_set_source"));
        assert!(!limited.allows("sap_search_object"));
    }

    #[test]
    fn package_groups_are_conjunctive_and_suppress_unverified_methods() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::load(dir.path()).unwrap();
        let pin = [11; 32];
        let global = Rules { packages: Some(vec!["/example/*".into(), "$tmp".into()]), ..unrestricted() };
        let local = Rules { packages: Some(vec!["/example/one".into()]), ..unrestricted() };
        store.set_global(&store.snapshot().unwrap().revision, global).unwrap();
        store.set_desktop(&store.snapshot().unwrap().revision, &hex::encode(pin), Some(local)).unwrap();
        let effective = store.effective(&pin).unwrap();
        assert_eq!(effective.package_scopes(), &[vec!["$TMP", "/EXAMPLE/*"], vec!["/EXAMPLE/ONE"]]);
        let allowed: Vec<_> = TOOLS.iter().copied().filter(|tool| effective.allows(tool)).collect();
        assert_eq!(allowed, ["sap_activate", "sap_create_object", "sap_get_source", "sap_lock",
            "sap_object_structure", "sap_search_object", "sap_set_source", "sap_unlock"]);
        store.set_global(&store.snapshot().unwrap().revision, Rules { packages: Some(Vec::new()), ..unrestricted() }).unwrap();
        assert!(!store.effective(&pin).unwrap().allows("sap_search_object"));
    }

    #[test]
    fn source_writes_require_all_component_actions_in_both_layers() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::load(dir.path()).unwrap();
        let pin = [22; 32];
        let all = ["sap_set_source", "sap_activate", "sap_lock", "sap_unlock"];
        for omitted in all {
            let reduced = Rules { actions: Some(all.iter().filter(|&&tool| tool != omitted)
                .map(|&name| name.to_owned()).collect()), ..unrestricted() };
            store.set_global(&store.snapshot().unwrap().revision, unrestricted()).unwrap();
            store.set_desktop(&store.snapshot().unwrap().revision, &hex::encode(pin), Some(reduced.clone())).unwrap();
            assert!(!store.effective(&pin).unwrap().allows("sap_set_source"));
            store.set_global(&store.snapshot().unwrap().revision, reduced).unwrap();
            store.set_desktop(&store.snapshot().unwrap().revision, &hex::encode(pin), Some(unrestricted())).unwrap();
            assert!(!store.effective(&pin).unwrap().allows("sap_set_source"));
        }
    }

    #[test]
    fn invalid_and_lost_policy_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::load(dir.path()).unwrap();
        let pin = "0".repeat(64);
        let rules = r#"{"read_only":false,"actions":null,"packages":null}"#;
        let duplicate = format!(r#"{{"global":{rules},"desktops":{{"{pin}":{rules},"{pin}":{rules}}}}}"#);
        fs::write(store.path(), duplicate).unwrap();
        assert!(store.effective(&[0; 32]).is_err());
        fs::write(store.path(), r#"{"global":{"read_only":false,"actions":null},"desktops":{}}"#).unwrap();
        assert!(store.snapshot().is_err());
        fs::remove_file(store.path()).unwrap();
        assert!(PolicyStore::load(dir.path()).is_err());
    }

    #[test]
    fn stale_editors_and_invalid_patterns_cannot_replace_the_policy() {
        let dir = tempfile::tempdir().unwrap();
        let first = PolicyStore::load(dir.path()).unwrap();
        let second = PolicyStore::load(dir.path()).unwrap();
        let revision = first.snapshot().unwrap().revision;
        first.set_global(&revision, Rules::desktop_default()).unwrap();
        assert!(second.set_global(&revision, unrestricted()).is_err());
        let current = second.snapshot().unwrap().revision;
        for bad in ["", "/NS/", "A*B", "A**", "/A/B/C", "A B", "../OTHER"] {
            let rules = Rules { packages: Some(vec![bad.into()]), ..unrestricted() };
            assert!(second.set_global(&current, rules).is_err());
        }
        assert_eq!(first.snapshot().unwrap().revision, current);
    }

    #[test]
    fn legacy_rules_require_separate_explicit_endpoint_assignments() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::load(dir.path()).unwrap();
        let desktop = [1; 32];
        let desktop_id = hex::encode(desktop);
        let endpoint = hex::encode([2; 32]);
        let second = hex::encode([3; 32]);
        let previous_desktops = BTreeMap::from([(desktop_id.as_str(), unrestricted())]);
        let old = serde_json::json!({"global": unrestricted(), "desktops": previous_desktops});
        fs::write(store.path(), serde_json::to_vec(&old).unwrap()).unwrap();
        let revision = store.snapshot().unwrap().revision;
        assert_eq!(store.endpoint_grants(&desktop).unwrap(), Vec::<String>::new());
        assert!(store.effective_for_endpoint(&desktop, &endpoint).unwrap().is_none());
        store.set_endpoint_grants(&revision, &desktop_id, vec![second.clone(), endpoint.clone()]).unwrap();
        assert!(store.set_global(&revision, Rules::desktop_default()).is_err());

        let reopened = PolicyStore::load(dir.path()).unwrap();
        assert_eq!(reopened.endpoint_grants(&desktop).unwrap(), [endpoint.clone(), second.clone()]);
        assert!(reopened.effective_for_endpoint(&desktop, &second).unwrap().unwrap().allows("sap_set_source"));
        assert!(reopened.effective_for_endpoint(&[4; 32], &second).unwrap().is_none());
        let revision = reopened.snapshot().unwrap().revision;
        reopened.set_desktop(&revision, &desktop_id, None).unwrap();
        assert!(!reopened.effective_for_endpoint(&desktop, &endpoint).unwrap().unwrap().allows("sap_set_source"));
        assert!(store.set_endpoint_grants(&revision, &desktop_id, vec![]).is_err());
        reopened.set_endpoint_grants(&reopened.snapshot().unwrap().revision, &desktop_id, vec![]).unwrap();
        assert!(store.effective_for_endpoint(&desktop, &endpoint).unwrap().is_none());
    }

    #[test]
    fn ambiguous_or_invalid_endpoint_grants_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::load(dir.path()).unwrap();
        let desktop = hex::encode([4; 32]);
        let endpoint = hex::encode([5; 32]);
        let revision = store.snapshot().unwrap().revision;
        for values in [vec![desktop.clone()], vec!["*".into()], vec![endpoint.clone(), endpoint.clone()]] {
            assert!(store.set_endpoint_grants(&revision, &desktop, values).is_err());
        }
        assert_eq!(store.snapshot().unwrap().revision, revision);
        let rules = r#"{"read_only":false,"actions":null,"packages":null}"#;
        let repeated = format!(r#"{{"global":{rules},"desktops":{{}},"endpoint_grants":{{"{desktop}":[],"{desktop}":["{endpoint}"]}}}}"#);
        fs::write(store.path(), repeated).unwrap();
        assert!(store.endpoint_grants(&[4; 32]).is_err());
        assert!(store.effective_for_endpoint(&[4; 32], &endpoint).is_err());
    }
}
