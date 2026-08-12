use std::path::PathBuf;

use ssdev_origin_policy::OriginPolicy;
use webplus_plugin_trust::TrustStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let policy = arguments
        .next()
        .ok_or("usage: verify_origin_policy <policy> <signature> <trust-store>")?;
    let signature = arguments
        .next()
        .ok_or("usage: verify_origin_policy <policy> <signature> <trust-store>")?;
    let trust_store = arguments
        .next()
        .ok_or("usage: verify_origin_policy <policy> <signature> <trust-store>")?;
    if arguments.next().is_some() {
        return Err("usage: verify_origin_policy <policy> <signature> <trust-store>".into());
    }
    let trust = TrustStore::load(&trust_store)?;
    let policy = OriginPolicy::load(&policy, &signature, &trust)?;
    println!("verified signed origin policy: {:?}", policy.summary());
    Ok(())
}
