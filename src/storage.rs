//! Owner-only files: private directories, atomic writes and size-limited reads.

use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

/// The largest credential or key file this package reads.
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Reads a credential file of at most [`MAX_CREDENTIAL_BYTES`] into memory that is wiped on drop.
///
/// # Errors
/// The file cannot be read or is larger than the limit.
pub fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?
        .take(MAX_CREDENTIAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_CREDENTIAL_BYTES,
        "Credential file exceeds the size limit."
    );
    Ok(bytes)
}

/// Creates a new owner-only directory. All secret files inherit a private parent on Windows.
/// No credential is written until the directory permissions have been installed successfully.
///
/// # Errors
/// The directory exists already or cannot be created or restricted to its owner; a directory
/// that was created but could not be restricted is removed again.
pub fn new_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    };
    #[cfg(not(unix))]
    let created = fs::create_dir(path);
    created.with_context(|| format!("Create a new private directory at {}.", path.display()))?;
    #[cfg(windows)]
    if let Err(error) = restrict_to_owner(path) {
        let _ = fs::remove_dir(path);
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_to_owner(path: &Path) -> Result<()> {
    use anyhow::ensure;
    use std::{os::windows::process::CommandExt, path::PathBuf, process::Command};

    let system =
        PathBuf::from(std::env::var_os("SystemRoot").context("Missing Windows system root.")?)
            .join("System32");
    let output = Command::new(system.join("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(0x0800_0000)
        .output()?;
    ensure!(
        output.status.success(),
        "Cannot identify the process owner."
    );
    let line = String::from_utf8_lossy(&output.stdout);
    let sid = line
        .trim()
        .rsplit_once(',')
        .context("Missing Windows user SID.")?
        .1
        .trim_matches('"');
    ensure!(
        sid.starts_with("S-1-") && sid[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-'),
        "Invalid Windows user SID."
    );
    let result = Command::new(system.join("icacls.exe"))
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &format!("*{sid}:(OI)(CI)F")])
        .creation_flags(0x0800_0000)
        .output()?;
    ensure!(
        result.status.success(),
        "Failed to restrict the private directory to its owner."
    );
    Ok(())
}

/// Writes `bytes` to a synced temporary file next to `path`; the caller persists it.
///
/// # Errors
/// `path` has no parent directory, or the file cannot be created, written or synced.
pub fn stage(path: &Path, bytes: &[u8]) -> Result<tempfile::NamedTempFile> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().context("Missing destination directory.")?)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    Ok(file)
}

/// Writes `bytes` to `path`, which must not exist yet, atomically.
///
/// # Errors
/// The file exists already or cannot be written.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    // PersistError owns the staged file. Drop it before the caller rolls back the directory.
    stage(path, bytes)?
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    Ok(())
}
