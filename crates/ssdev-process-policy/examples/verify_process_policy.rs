use std::error::Error;
use std::path::PathBuf;

use ssdev_process_policy::ProcessPolicy;
use webplus_plugin_trust::TrustStore;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let policy = required(&mut arguments, "process policy")?;
    let signature = required(&mut arguments, "process policy signature")?;
    let trust_store = required(&mut arguments, "trust store")?;
    if arguments.next().is_some() {
        return Err("too many arguments".into());
    }
    let trust_store = TrustStore::load(&trust_store)?;
    let policy = ProcessPolicy::load(&policy, &signature, &trust_store)?;
    println!(
        "verified signed process policy with {} entries",
        policy.len()
    );
    Ok(())
}

fn required(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name} argument").into())
}
