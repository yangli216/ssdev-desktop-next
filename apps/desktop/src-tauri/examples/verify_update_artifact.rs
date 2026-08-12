use std::path::PathBuf;

fn main() {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let policy = arguments.next().unwrap_or_else(|| usage());
    let package = arguments.next().unwrap_or_else(|| usage());
    let signature = arguments.next().unwrap_or_else(|| usage());
    if arguments.next().is_some() {
        usage();
    }
    match ssdev_desktop_core::verify_update_artifact_files(&policy, &package, &signature) {
        Ok(bytes) => println!("verified updater artifact ({bytes} bytes)"),
        Err(error) => {
            eprintln!("updater artifact rejected: {error}");
            std::process::exit(1);
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: verify_update_artifact <app-update.json> <update-package> <update-package.sig>"
    );
    std::process::exit(2);
}
