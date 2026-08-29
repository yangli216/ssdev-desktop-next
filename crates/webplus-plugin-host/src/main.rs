#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::collections::HashSet;
use std::env;
use std::path::{Component, Path};
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(not(windows))]
use tokio::io::{stdin, stdout};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use webplus_ipc::{read_frame_async, write_frame_async};
use webplus_native::NativePlugin;
use webplus_plugin_config::{verify_local_mapping_integrity_with_files, PluginManifest};
use webplus_plugin_trust::TrustStore;
use webplus_protocol::{
    HostCommand, HostPayload, HostRequest, HostResponse, InvokeRequest, InvokeResponse,
    PluginArchitecture, HOST_PROTOCOL_VERSION,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("webplus-plugin-host: host-failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = HostArguments::parse(env::args().skip(1))?;
    if arguments.architecture != compiled_architecture() {
        return Err("plugin host binary architecture does not match the requested route".into());
    }
    let (mut input, mut output) = open_transport(&arguments).await?;
    let manifest = PluginManifest::load(&arguments.plugin_id, &arguments.plugin_dir)?;
    let verified_files = if arguments.allow_unsigned {
        if !cfg!(debug_assertions) {
            return Err("release plugin hosts refuse --allow-unsigned".into());
        }
        None
    } else if let Some(local_mapping_root) = arguments.local_mapping_root.as_deref() {
        require_local_mapping_path(
            Path::new(&arguments.plugin_dir),
            Path::new(local_mapping_root),
        )?;
        let expected = arguments
            .local_mapping_integrity_sha256
            .as_deref()
            .ok_or("local mapping hosts require an approved integrity identity")?;
        let actual = manifest
            .local_mapping_integrity_sha256
            .as_deref()
            .ok_or("local mapping does not contain a verified integrity document")?;
        if actual != expected {
            return Err("local mapping integrity identity changed after route approval".into());
        }
        let verified =
            verify_local_mapping_integrity_with_files(&manifest.plugin_dir, &manifest.services)?;
        if verified.document_sha256 != expected {
            return Err("local mapping integrity identity changed during host startup".into());
        }
        Some(verified.files)
    } else {
        let trust_store_path = arguments
            .trust_store
            .as_deref()
            .ok_or("signed plugin hosts require --trust-store")?;
        let trust_store = TrustStore::load(std::path::Path::new(&trust_store_path))?;
        Some(trust_store.verify_with_file_inventory(&manifest)?)
    };
    let allowed_services = manifest
        .services
        .iter()
        .filter(|service| service.architecture == arguments.architecture)
        .map(|service| service.service_id.clone())
        .collect::<HashSet<_>>();
    let (mut native_worker, native_preflight_code) =
        match NativeWorker::spawn(manifest, arguments.architecture, verified_files) {
            Ok(worker) => (Some(worker), None),
            Err(code) => (None, Some(code)),
        };

    while let Some(request) = read_frame_async::<_, HostRequest>(&mut input).await? {
        let request_id = request.request_id;
        let response = if request.protocol_version != HOST_PROTOCOL_VERSION {
            HostResponse::error(
                request_id,
                "protocol_version",
                format!(
                    "unsupported protocol version {}, expected {}",
                    request.protocol_version, HOST_PROTOCOL_VERSION
                ),
            )
        } else {
            match request.command {
                HostCommand::Health if native_worker.is_some() => HostResponse::ok(
                    request_id,
                    HostPayload::Health {
                        plugin_id: arguments.plugin_id.clone(),
                    },
                ),
                HostCommand::Health => HostResponse::error(
                    request_id,
                    native_preflight_code.unwrap_or("native_preflight"),
                    "native component preflight failed",
                ),
                HostCommand::Invoke {
                    plugin_id: requested_plugin,
                    request,
                } if requested_plugin == arguments.plugin_id
                    && !allowed_services.contains(&request.service_id) =>
                {
                    HostResponse::error(
                        request_id,
                        "architecture_mismatch",
                        "service is not assigned to this native host architecture",
                    )
                }
                HostCommand::Invoke {
                    plugin_id: requested_plugin,
                    request,
                } if requested_plugin == arguments.plugin_id => match native_worker.as_ref() {
                    Some(worker) => {
                        let response = worker.invoke(request).await?;
                        HostResponse::ok(request_id, HostPayload::Invoke { response })
                    }
                    None => HostResponse::error(
                        request_id,
                        native_preflight_code.unwrap_or("native_preflight"),
                        "native component preflight failed",
                    ),
                },
                HostCommand::Invoke {
                    plugin_id: requested_plugin,
                    ..
                } => HostResponse::error(
                    request_id,
                    "plugin_mismatch",
                    format!(
                        "worker for plugin [{}] rejected request for [{}]",
                        arguments.plugin_id, requested_plugin
                    ),
                ),
                HostCommand::Shutdown => {
                    if let Some(worker) = native_worker.as_mut() {
                        worker.shutdown()?;
                    }
                    write_frame_async(
                        &mut output,
                        &HostResponse::ok(request_id, HostPayload::Shutdown),
                    )
                    .await?;
                    break;
                }
            }
        };
        write_frame_async(&mut output, &response).await?;
    }
    Ok(())
}

fn compiled_architecture() -> PluginArchitecture {
    if cfg!(target_pointer_width = "32") {
        PluginArchitecture::X86
    } else {
        PluginArchitecture::X64
    }
}

type HostReader = Box<dyn AsyncRead + Unpin + Send>;
type HostWriter = Box<dyn AsyncWrite + Unpin + Send>;

#[cfg(not(windows))]
async fn open_transport(
    _arguments: &HostArguments,
) -> Result<(HostReader, HostWriter), Box<dyn std::error::Error>> {
    Ok((Box::new(stdin()), Box::new(stdout())))
}

#[cfg(windows)]
async fn open_transport(
    arguments: &HostArguments,
) -> Result<(HostReader, HostWriter), Box<dyn std::error::Error>> {
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let pipe = ClientOptions::new().open(&arguments.ipc_pipe)?;
    let mut actual_controller = 0;
    let handle = HANDLE(pipe.as_raw_handle());
    unsafe { GetNamedPipeServerProcessId(handle, &mut actual_controller) }?;
    if actual_controller != arguments.controller_pid {
        return Err("named-pipe server is not the expected controller process".into());
    }
    let (reader, writer) = tokio::io::split(pipe);
    Ok((Box::new(reader), Box::new(writer)))
}

#[derive(Debug, PartialEq, Eq)]
struct HostArguments {
    plugin_id: String,
    plugin_dir: String,
    architecture: PluginArchitecture,
    trust_store: Option<String>,
    allow_unsigned: bool,
    local_mapping_root: Option<String>,
    local_mapping_integrity_sha256: Option<String>,
    #[cfg(windows)]
    ipc_pipe: String,
    #[cfg(windows)]
    controller_pid: u32,
}

impl HostArguments {
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut arguments = arguments.into_iter();
        let mut plugin_id = None;
        let mut plugin_dir = None;
        let mut architecture = None;
        let mut trust_store = None;
        let mut allow_unsigned = false;
        let mut allow_local_mapping = false;
        let mut local_mapping_root = None;
        let mut local_mapping_integrity_sha256 = None;
        #[cfg(windows)]
        let mut ipc_pipe = None;
        #[cfg(windows)]
        let mut controller_pid = None;

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--plugin-id" => set_once(
                    &mut plugin_id,
                    "--plugin-id",
                    take_value(&mut arguments, "--plugin-id")?,
                )?,
                "--plugin-dir" => set_once(
                    &mut plugin_dir,
                    "--plugin-dir",
                    take_value(&mut arguments, "--plugin-dir")?,
                )?,
                "--architecture" => set_once(
                    &mut architecture,
                    "--architecture",
                    take_value(&mut arguments, "--architecture")?,
                )?,
                "--trust-store" => set_once(
                    &mut trust_store,
                    "--trust-store",
                    take_value(&mut arguments, "--trust-store")?,
                )?,
                "--allow-unsigned" if !allow_unsigned => allow_unsigned = true,
                "--allow-unsigned" => return Err("duplicate argument --allow-unsigned".into()),
                "--allow-local-mapping" if !allow_local_mapping => allow_local_mapping = true,
                "--allow-local-mapping" => {
                    return Err("duplicate argument --allow-local-mapping".into())
                }
                "--local-mapping-root" => set_once(
                    &mut local_mapping_root,
                    "--local-mapping-root",
                    take_value(&mut arguments, "--local-mapping-root")?,
                )?,
                "--local-mapping-integrity-sha256" => set_once(
                    &mut local_mapping_integrity_sha256,
                    "--local-mapping-integrity-sha256",
                    take_value(&mut arguments, "--local-mapping-integrity-sha256")?,
                )?,
                #[cfg(windows)]
                "--ipc-pipe" => set_once(
                    &mut ipc_pipe,
                    "--ipc-pipe",
                    take_value(&mut arguments, "--ipc-pipe")?,
                )?,
                #[cfg(windows)]
                "--controller-pid" => set_once(
                    &mut controller_pid,
                    "--controller-pid",
                    take_value(&mut arguments, "--controller-pid")?,
                )?,
                _ => return Err(format!("unknown argument {argument}")),
            }
        }

        #[cfg(windows)]
        let controller_pid = controller_pid
            .ok_or("missing required argument --controller-pid")?
            .parse::<u32>()
            .map_err(|_| "--controller-pid must be an unsigned integer")?;
        if allow_unsigned && allow_local_mapping {
            return Err("unsigned and local mapping modes are mutually exclusive".into());
        }
        if allow_local_mapping != local_mapping_root.is_some()
            || allow_local_mapping != local_mapping_integrity_sha256.is_some()
        {
            return Err(
                "--allow-local-mapping, --local-mapping-root, and --local-mapping-integrity-sha256 must be supplied together".into(),
            );
        }
        if let Some(digest) = local_mapping_integrity_sha256.as_deref() {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("--local-mapping-integrity-sha256 must be lowercase SHA-256".into());
            }
        }
        if trust_store.is_some() && (allow_unsigned || allow_local_mapping) {
            return Err("trust modes are mutually exclusive".into());
        }
        Ok(Self {
            plugin_id: plugin_id.ok_or("missing required argument --plugin-id")?,
            plugin_dir: plugin_dir.ok_or("missing required argument --plugin-dir")?,
            architecture: match architecture
                .ok_or("missing required argument --architecture")?
                .as_str()
            {
                "x86" => PluginArchitecture::X86,
                "x64" => PluginArchitecture::X64,
                _ => return Err("--architecture must be x86 or x64".into()),
            },
            trust_store,
            allow_unsigned,
            local_mapping_root,
            local_mapping_integrity_sha256,
            #[cfg(windows)]
            ipc_pipe: ipc_pipe.ok_or("missing required argument --ipc-pipe")?,
            #[cfg(windows)]
            controller_pid,
        })
    }
}

fn require_local_mapping_path(plugin_dir: &Path, root: &Path) -> Result<(), String> {
    let root = root
        .canonicalize()
        .map_err(|_| "local mapping root is unavailable")?;
    let plugin_dir = plugin_dir
        .canonicalize()
        .map_err(|_| "local mapping directory is unavailable")?;
    let relative = plugin_dir
        .strip_prefix(&root)
        .map_err(|_| "local mapping directory is outside the configured root")?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("local mapping directory is not a bounded child path".into());
    }
    Ok(())
}

fn take_value(arguments: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    arguments
        .next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} requires a non-empty value"))
}

fn set_once(slot: &mut Option<String>, name: &str, value: String) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate argument {name}"));
    }
    Ok(())
}

enum NativeCommand {
    Invoke {
        request: InvokeRequest,
        reply: oneshot::Sender<InvokeResponse>,
    },
    Shutdown,
}

struct NativeWorker {
    sender: Option<mpsc::Sender<NativeCommand>>,
    thread: Option<JoinHandle<()>>,
}

impl NativeWorker {
    fn spawn(
        manifest: PluginManifest,
        architecture: PluginArchitecture,
        verified_files: Option<std::collections::BTreeMap<String, String>>,
    ) -> Result<Self, &'static str> {
        let (sender, receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(format!("webplus-native-{}", manifest.plugin_id))
            .spawn(move || {
                let plugin = match verified_files {
                    Some(files) => NativePlugin::new_verified(manifest, files),
                    None => Ok(NativePlugin::new(manifest)),
                };
                let mut plugin = match plugin {
                    Ok(plugin) => plugin,
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.diagnostic_code()));
                        return;
                    }
                };
                if let Err(error) = plugin.preflight(architecture) {
                    let _ = ready_sender.send(Err(error.diagnostic_code()));
                    return;
                }
                if ready_sender.send(Ok(())).is_err() {
                    return;
                }
                loop {
                    match receiver.recv_timeout(Duration::from_millis(16)) {
                        Ok(NativeCommand::Invoke { request, reply }) => {
                            let _ = reply.send(plugin.invoke(&request));
                        }
                        Ok(NativeCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => plugin.pump_messages(),
                    }
                }
            })
            .map_err(|_| "native_worker_unavailable")?;
        match ready_receiver.recv() {
            Ok(Ok(())) => {}
            Ok(Err(code)) => {
                let _ = thread.join();
                return Err(code);
            }
            Err(_) => {
                let _ = thread.join();
                return Err("native_worker_unavailable");
            }
        }
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }

    async fn invoke(
        &self,
        request: InvokeRequest,
    ) -> Result<InvokeResponse, Box<dyn std::error::Error>> {
        let (reply, response) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or("native worker has stopped")?
            .send(NativeCommand::Invoke { request, reply })
            .map_err(|_| "native worker has stopped")?;
        response
            .await
            .map_err(|_| "native worker stopped before replying".into())
    }

    fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(NativeCommand::Shutdown);
        }
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "native worker thread panicked")?;
        }
        Ok(())
    }
}

impl Drop for NativeWorker {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required_platform_arguments() -> Vec<String> {
        #[cfg(windows)]
        {
            let mut arguments = vec!["--architecture".into(), "x86".into()];
            arguments.extend([
                "--ipc-pipe".into(),
                r"\\.\pipe\fixture".into(),
                "--controller-pid".into(),
                "42".into(),
            ]);
            arguments
        }
        #[cfg(not(windows))]
        {
            vec!["--architecture".into(), "x86".into()]
        }
    }

    #[test]
    fn option_shaped_values_are_not_reparsed_as_flags() {
        let mut input = vec![
            "--plugin-id".into(),
            "--allow-unsigned".into(),
            "--plugin-dir".into(),
            "--ipc-pipe".into(),
        ];
        input.extend(required_platform_arguments());
        let parsed = HostArguments::parse(input).unwrap();

        assert_eq!(parsed.plugin_id, "--allow-unsigned");
        assert_eq!(parsed.plugin_dir, "--ipc-pipe");
        assert!(!parsed.allow_unsigned);
    }

    #[test]
    fn duplicate_and_unknown_arguments_are_rejected() {
        let duplicate = vec![
            "--plugin-id".into(),
            "reader".into(),
            "--plugin-id".into(),
            "other".into(),
            "--plugin-dir".into(),
            "fixture".into(),
        ];
        assert!(HostArguments::parse(duplicate).is_err());

        let unknown = vec![
            "--plugin-id".into(),
            "reader".into(),
            "--plugin-dir".into(),
            "fixture".into(),
            "--execute".into(),
            "anything".into(),
        ];
        assert!(HostArguments::parse(unknown).is_err());
    }

    #[test]
    fn local_mapping_mode_requires_a_root_and_excludes_other_trust_modes() {
        let mut valid = vec![
            "--plugin-id".into(),
            "reader.local".into(),
            "--plugin-dir".into(),
            "fixture".into(),
            "--allow-local-mapping".into(),
            "--local-mapping-root".into(),
            "mappings".into(),
            "--local-mapping-integrity-sha256".into(),
            "a".repeat(64),
        ];
        valid.extend(required_platform_arguments());
        let parsed = HostArguments::parse(valid).unwrap();
        assert_eq!(parsed.local_mapping_root.as_deref(), Some("mappings"));
        assert_eq!(parsed.architecture, PluginArchitecture::X86);

        let missing_root = vec![
            "--plugin-id".into(),
            "reader.local".into(),
            "--plugin-dir".into(),
            "fixture".into(),
            "--allow-local-mapping".into(),
        ];
        assert!(HostArguments::parse(missing_root).is_err());

        let conflicting = vec![
            "--plugin-id".into(),
            "reader.local".into(),
            "--plugin-dir".into(),
            "fixture".into(),
            "--allow-local-mapping".into(),
            "--local-mapping-root".into(),
            "mappings".into(),
            "--local-mapping-integrity-sha256".into(),
            "a".repeat(64),
            "--trust-store".into(),
            "trust.json".into(),
        ];
        assert!(HostArguments::parse(conflicting).is_err());
    }

    #[test]
    fn local_mapping_path_must_be_beneath_the_configured_root() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("reader.local");
        std::fs::create_dir(&child).unwrap();
        assert!(require_local_mapping_path(&child, root.path()).is_ok());
        assert!(require_local_mapping_path(root.path(), root.path()).is_err());

        let outside = tempfile::tempdir().unwrap();
        assert!(require_local_mapping_path(outside.path(), root.path()).is_err());
    }

    #[test]
    fn native_worker_reports_component_preflight_before_serving_health() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("probe.exe"), b"not executed").unwrap();
        std::fs::write(
            root.path().join("api.json"),
            r#"{"serviceId":"process.probe","mainClass":"probe.exe","mainType":"exe","architecture":"x86","methods":[{"name":"run"}]}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("process-probe", root.path()).unwrap();
        let mut mismatched_inventory = std::collections::BTreeMap::new();
        mismatched_inventory.insert("probe.exe".into(), "0".repeat(64));
        assert_eq!(
            NativeWorker::spawn(
                manifest.clone(),
                PluginArchitecture::X86,
                Some(mismatched_inventory),
            )
            .err()
            .unwrap(),
            "native_process"
        );
        let mut worker =
            NativeWorker::spawn(manifest.clone(), PluginArchitecture::X86, None).unwrap();
        worker.shutdown().unwrap();

        std::fs::remove_file(root.path().join("probe.exe")).unwrap();
        assert_eq!(
            NativeWorker::spawn(manifest, PluginArchitecture::X86, None)
                .err()
                .unwrap(),
            "native_component_missing"
        );
    }

    #[test]
    fn compiled_architecture_matches_the_binary_pointer_width() {
        assert_eq!(
            compiled_architecture(),
            if cfg!(target_pointer_width = "32") {
                PluginArchitecture::X86
            } else {
                PluginArchitecture::X64
            }
        );
    }
}
