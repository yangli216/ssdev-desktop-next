use std::env;
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
use webplus_plugin_config::PluginManifest;
use webplus_plugin_trust::TrustStore;
use webplus_protocol::{
    HostCommand, HostPayload, HostRequest, HostResponse, InvokeRequest, InvokeResponse,
    HOST_PROTOCOL_VERSION,
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
    let (mut input, mut output) = open_transport(&arguments).await?;
    let manifest = PluginManifest::load(&arguments.plugin_id, &arguments.plugin_dir)?;
    if arguments.allow_unsigned {
        if !cfg!(debug_assertions) {
            return Err("release plugin hosts refuse --allow-unsigned".into());
        }
    } else {
        let trust_store_path = arguments
            .trust_store
            .as_deref()
            .ok_or("signed plugin hosts require --trust-store")?;
        let trust_store = TrustStore::load(std::path::Path::new(&trust_store_path))?;
        trust_store.verify(&manifest)?;
    }
    let mut native_worker = NativeWorker::spawn(manifest)?;

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
                HostCommand::Health => HostResponse::ok(
                    request_id,
                    HostPayload::Health {
                        plugin_id: arguments.plugin_id.clone(),
                    },
                ),
                HostCommand::Invoke {
                    plugin_id: requested_plugin,
                    request,
                } if requested_plugin == arguments.plugin_id => {
                    let response = native_worker.invoke(request).await?;
                    HostResponse::ok(request_id, HostPayload::Invoke { response })
                }
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
                    native_worker.shutdown()?;
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
    trust_store: Option<String>,
    allow_unsigned: bool,
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
        let mut trust_store = None;
        let mut allow_unsigned = false;
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
                "--trust-store" => set_once(
                    &mut trust_store,
                    "--trust-store",
                    take_value(&mut arguments, "--trust-store")?,
                )?,
                "--allow-unsigned" if !allow_unsigned => allow_unsigned = true,
                "--allow-unsigned" => return Err("duplicate argument --allow-unsigned".into()),
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
        Ok(Self {
            plugin_id: plugin_id.ok_or("missing required argument --plugin-id")?,
            plugin_dir: plugin_dir.ok_or("missing required argument --plugin-dir")?,
            trust_store,
            allow_unsigned,
            #[cfg(windows)]
            ipc_pipe: ipc_pipe.ok_or("missing required argument --ipc-pipe")?,
            #[cfg(windows)]
            controller_pid,
        })
    }
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
    fn spawn(manifest: PluginManifest) -> Result<Self, std::io::Error> {
        let (sender, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name(format!("webplus-native-{}", manifest.plugin_id))
            .spawn(move || {
                let mut plugin = NativePlugin::new(manifest);
                loop {
                    match receiver.recv_timeout(Duration::from_millis(16)) {
                        Ok(NativeCommand::Invoke { request, reply }) => {
                            let _ = reply.send(plugin.invoke(&request));
                        }
                        Ok(NativeCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => plugin.pump_messages(),
                    }
                }
            })?;
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
            vec![
                "--ipc-pipe".into(),
                r"\\.\pipe\fixture".into(),
                "--controller-pid".into(),
                "42".into(),
            ]
        }
        #[cfg(not(windows))]
        {
            Vec::new()
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
}
