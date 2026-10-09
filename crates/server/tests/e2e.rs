use shikra_core::config::{LogFormat, ServerConfig};
use shikra_implant::{run_agent, AgentConfig};
use shikra_transport::tls::load_ca_pem;
use std::time::Duration;
use tokio::net::TcpListener;

fn test_database_url() -> Option<String> {
    std::env::var("SHIKRA_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
}

async fn wait_for_session(
    client: &mut shikra_client::OperatorClient,
    timeout: Duration,
) -> anyhow::Result<shikra_proto::v1::SessionInfo> {
    // Tests share one database and may run in parallel; sessions from
    // earlier or finished tests linger as non-dead until the reaper catches
    // up. Accept only sessions that checked in within the last few seconds
    // so a stale session can never swallow a task we submit.
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let cutoff =
            prost_types::Timestamp::from(std::time::SystemTime::now() - Duration::from_secs(10));
        let sessions = client.sessions().await?;
        let found = sessions.into_iter().find(|session| {
            session
                .last_seen
                .as_ref()
                .is_some_and(|seen| (seen.seconds, seen.nanos) >= (cutoff.seconds, cutoff.nanos))
        });
        if let Some(session) = found {
            return Ok(session);
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for agent check-in");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn first_seen_after(
    session: &shikra_proto::v1::SessionInfo,
    mark: &prost_types::Timestamp,
) -> bool {
    session
        .first_seen
        .as_ref()
        .is_some_and(|seen| (seen.seconds, seen.nanos) >= (mark.seconds, mark.nanos))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_end_to_end_communication() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
        )
        .try_init();

    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;

    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;
    let http_addr = http_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    // Bootstrap once to learn enrollment/operator tokens (server reuses the same files).
    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);

    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });

    // Wait until the gRPC port accepts connections.
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());

    // --- Agent connects ---
    let agent_config = AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token: enroll_token.clone(),
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    };
    let agent_task = tokio::spawn(async move { run_agent(agent_config).await });

    // --- Operator connects ---
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        token: operator_token.clone(),
        domain: "localhost".into(),
    })
    .await?;

    let version = client.version().await?;
    assert_eq!(version, env!("CARGO_PKG_VERSION"));

    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;
    assert!(!session.hostname.is_empty());

    // --- Encrypted task round-trip ---
    let results = client
        .submit_task(
            &session.id,
            "echo",
            serde_json::json!("encrypted-hello"),
            Vec::new(),
        )
        .await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].exit_code, 0);
    assert_eq!(
        String::from_utf8_lossy(&results[0].output),
        "encrypted-hello"
    );

    // --- Shell execution with captured output ---
    let shell = client
        .run_task(
            &session.id,
            "shell",
            serde_json::json!({ "command": "echo shell-e2e" }),
        )
        .await?;
    assert_eq!(shell.exit_code, 0);
    assert!(String::from_utf8_lossy(&shell.output).contains("shell-e2e"));

    // --- File upload/download round-trip through the encrypted channel ---
    let workspace = tempfile::tempdir()?;
    let local_path = workspace.path().join("payload.bin");
    let mut payload = Vec::with_capacity(2 * 1024 * 1024 + 7);
    for i in 0..(2 * 1024 * 1024 + 7) {
        payload.push((i % 251) as u8);
    }
    std::fs::write(&local_path, &payload)?;

    let remote_name = "shikra-e2e-payload.bin";
    let uploaded = client.upload(&session.id, &local_path, remote_name).await?;
    assert_eq!(uploaded, payload.len() as u64);

    let stat = client
        .run_task(
            &session.id,
            "stat",
            serde_json::json!({ "path": remote_name }),
        )
        .await?;
    assert_eq!(stat.exit_code, 0);
    let stat_json: serde_json::Value = serde_json::from_slice(&stat.output)?;
    assert_eq!(stat_json["size"].as_u64(), Some(payload.len() as u64));

    let download_path = workspace.path().join("downloaded.bin");
    let downloaded = client
        .download(&session.id, remote_name, &download_path)
        .await?;
    assert_eq!(downloaded, payload.len() as u64);
    let roundtrip = std::fs::read(&download_path)?;
    assert_eq!(roundtrip, payload);

    // --- Directory listing and cleanup ---
    let ls = client
        .run_task(&session.id, "ls", serde_json::json!({ "path": "." }))
        .await?;
    assert_eq!(ls.exit_code, 0);
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&ls.output)?;
    assert!(entries
        .iter()
        .any(|entry| entry["name"].as_str() == Some(remote_name)));

    let rm = client
        .run_task(
            &session.id,
            "rm",
            serde_json::json!({ "path": remote_name }),
        )
        .await?;
    assert_eq!(rm.exit_code, 0);

    // --- Recon tasks return data ---
    let env = client
        .run_task(&session.id, "env", serde_json::Value::Null)
        .await?;
    assert_eq!(env.exit_code, 0);
    assert!(String::from_utf8_lossy(&env.output).contains('{'));

    let ps = client
        .run_task(&session.id, "ps", serde_json::Value::Null)
        .await?;
    assert_eq!(ps.exit_code, 0);
    assert!(!ps.output.is_empty());

    // --- BOF execution through the encrypted channel (host-arch fixture) ---
    let (bof_fixture, bof_marker) = if cfg!(target_arch = "aarch64") {
        (
            include_bytes!("../../implant/tests/fixtures/hello_bof_arm64.obj").to_vec(),
            "arm-bof-ok",
        )
    } else {
        (
            include_bytes!("../../implant/tests/fixtures/hello_bof.obj").to_vec(),
            "[+] bof says hello",
        )
    };
    let bof = client
        .submit_task(
            &session.id,
            "bof",
            serde_json::json!({ "args": "bof-args" }),
            bof_fixture,
        )
        .await?;
    assert_eq!(
        bof[0].exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&bof[0].output)
    );
    let bof_output = String::from_utf8_lossy(&bof[0].output);
    assert!(
        bof_output.contains(bof_marker),
        "BOF output missing marker: {bof_output:?}"
    );

    // --- WASM extension load/run/remove through the encrypted channel ---
    let wasm_module = wat::parse_str(
        r#"
        (module
          (import "env" "host_output" (func $host_output (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 512) "wasm-e2e-ok")
          (func (export "alloc") (param i32) (result i32) (i32.const 1024))
          (func (export "run") (param i32 i32) (result i32)
            (call $host_output (i32.const 512) (i32.const 11))
            (call $host_output (local.get 0) (local.get 1))
            (i32.const 0)))
        "#,
    )
    .expect("compile wat");

    let loaded = client
        .submit_task(
            &session.id,
            "wasm_load",
            serde_json::json!({ "name": "e2e-ext" }),
            wasm_module,
        )
        .await?;
    assert_eq!(
        loaded[0].exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&loaded[0].output)
    );
    assert!(String::from_utf8_lossy(&loaded[0].output).contains("registered e2e-ext"));

    let listed = client
        .run_task(&session.id, "wasm_list", serde_json::Value::Null)
        .await?;
    assert_eq!(listed.exit_code, 0);
    assert!(String::from_utf8_lossy(&listed.output).contains("e2e-ext"));

    let ran = client
        .run_task(
            &session.id,
            "wasm_run",
            serde_json::json!({ "name": "e2e-ext", "args": "wasm-args" }),
        )
        .await?;
    assert_eq!(ran.exit_code, 0, "{}", String::from_utf8_lossy(&ran.output));
    let ran_output = String::from_utf8_lossy(&ran.output);
    assert!(ran_output.contains("wasm-e2e-ok"), "output: {ran_output:?}");
    assert!(ran_output.contains("wasm-args"), "output: {ran_output:?}");

    let removed = client
        .run_task(
            &session.id,
            "wasm_remove",
            serde_json::json!({ "name": "e2e-ext" }),
        )
        .await?;
    assert_eq!(
        removed.exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&removed.output)
    );

    // --- Wrong enrollment token is rejected ---
    let bad_agent = run_agent(AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token: "0".repeat(64),
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(5),
    })
    .await;
    assert!(bad_agent.is_err(), "wrong enrollment token must fail");

    // --- Wrong operator token is rejected ---
    let mut bad_client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        token: "0".repeat(64),
        domain: "localhost".into(),
    })
    .await?;
    assert!(
        bad_client.version().await.is_err(),
        "wrong operator token must fail"
    );

    // --- Wrong pinned server identity is rejected by the agent ---
    let mut wrong_identity = server_identity;
    wrong_identity[0] ^= 0xff;
    let bad_pin = run_agent(AgentConfig {
        endpoint,
        ca_pem,
        server_identity: wrong_identity,
        enroll_token,
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(5),
    })
    .await;
    assert!(bad_pin.is_err(), "wrong pinned server identity must fail");

    agent_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

async fn wait_for_port(addr: std::net::SocketAddr) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("server did not start listening on {addr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_beacon_encrypted_poll_communication() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;

    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;
    let http_addr = http_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });

    wait_for_port(grpc_addr).await?;
    wait_for_port(http_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;

    // --- HTTP beacon enrolls and polls on a fast schedule ---
    let profiles =
        shikra_transport::profile::ProfileSet::single(shikra_transport::profile::C2Profile {
            poll_interval_secs: 1,
            jitter_secs: 0,
            ..Default::default()
        });

    let beacon_task = tokio::spawn(async move {
        shikra_implant::run_beacon(shikra_implant::BeaconConfig {
            base_url: format!("http://127.0.0.1:{}", http_addr.port()),
            ca_pem: Some(ca_pem),
            server_identity,
            enroll_token,
            profiles,
            max_runtime_secs: Some(60),
        })
        .await
    });

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem: load_ca_pem(state_dir.path())?,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;
    assert_eq!(
        session.kind,
        shikra_proto::v1::SessionKind::Beacon as i32,
        "session must be registered as a beacon"
    );

    // --- Task executes via beacon poll and returns through the encrypted channel ---
    let result = client
        .run_task(
            &session.id,
            "shell",
            serde_json::json!({ "command": "echo beacon-e2e" }),
        )
        .await?;
    assert_eq!(result.exit_code, 0, "beacon task failed");
    assert!(String::from_utf8_lossy(&result.output).contains("beacon-e2e"));

    // --- Upload/download also work through poll batching ---
    let workspace = tempfile::tempdir()?;
    let local_path = workspace.path().join("beacon-payload.bin");
    let payload: Vec<u8> = (0..700_000u32).map(|i| (i % 249) as u8).collect();
    std::fs::write(&local_path, &payload)?;

    let uploaded = client
        .upload(&session.id, &local_path, "beacon-payload.bin")
        .await?;
    assert_eq!(uploaded, payload.len() as u64);

    let download_path = workspace.path().join("beacon-downloaded.bin");
    let downloaded = client
        .download(&session.id, "beacon-payload.bin", &download_path)
        .await?;
    assert_eq!(downloaded, payload.len() as u64);
    assert_eq!(std::fs::read(&download_path)?, payload);

    beacon_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

async fn spawn_echo_server() -> anyhow::Result<std::net::SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_portfwd_rportfwd_tunnels() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: http_listener.local_addr()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;
    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());

    // Session-mode agent.
    let agent_task = tokio::spawn(run_agent(AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token,
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    }));

    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;
    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    let echo_addr = spawn_echo_server().await?;

    // --- Raw operator tunnel: open 127.0.0.1:echo through the agent ---
    let manager = std::sync::Arc::new(client.tunnel_manager(&session.id));
    {
        let mut tunnel = manager
            .open(&session.id, "127.0.0.1", echo_addr.port())
            .await?;
        tunnel.tx.send(b"tunnel-hello".to_vec()).await?;
        let echoed = tokio::time::timeout(Duration::from_secs(10), tunnel.rx.recv())
            .await?
            .expect("echo data");
        assert_eq!(echoed, b"tunnel-hello");
    }

    // --- Local SOCKS5 proxy bridging into the tunnel ---
    let socks_listener = TcpListener::bind("127.0.0.1:0").await?;
    let socks_addr = socks_listener.local_addr()?;
    let socks_manager = manager.clone();
    let socks_session = session.id.clone();
    let socks_task = tokio::spawn(async move {
        shikra_client::run_socks5(socks_manager, socks_session, socks_listener).await
    });

    let mut socks_client = tokio::net::TcpStream::connect(socks_addr).await?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Greeting: version 5, one method: no-auth.
    socks_client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    socks_client.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [0x05, 0x00]);
    // CONNECT to 127.0.0.1:echo via IPv4.
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&[127, 0, 0, 1]);
    request.extend_from_slice(&echo_addr.port().to_be_bytes());
    socks_client.write_all(&request).await?;
    let mut reply = [0u8; 10];
    socks_client.read_exact(&mut reply).await?;
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT rejected");
    socks_client.write_all(b"socks-hello").await?;
    let mut echo = [0u8; 11];
    socks_client.read_exact(&mut echo).await?;
    assert_eq!(&echo, b"socks-hello");

    // --- Local port forward ---
    let fwd_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fwd_addr = fwd_listener.local_addr()?;
    let fwd_manager = manager.clone();
    let fwd_session = session.id.clone();
    let fwd_task = tokio::spawn(async move {
        shikra_client::run_portfwd(
            fwd_manager,
            fwd_session,
            fwd_listener,
            "127.0.0.1".into(),
            echo_addr.port(),
        )
        .await
    });

    let mut fwd_client = tokio::net::TcpStream::connect(fwd_addr).await?;
    fwd_client.write_all(b"portfwd-hello").await?;
    let mut echo = [0u8; 13];
    fwd_client.read_exact(&mut echo).await?;
    assert_eq!(&echo, b"portfwd-hello");

    // --- Remote port forward: agent listens, server dials the echo target ---
    let rport_listener = TcpListener::bind("127.0.0.1:0").await?;
    let rport_addr = rport_listener.local_addr()?;
    drop(rport_listener); // free the port for the agent to bind

    let status = client
        .start_rportfwd(&session.id, &rport_addr.to_string(), &echo_addr.to_string())
        .await?;
    assert!(status.running, "rportfwd did not start: {}", status.message);

    // Give the agent a moment to bind the listener.
    let mut rport_client = None;
    for _ in 0..50 {
        match tokio::net::TcpStream::connect(rport_addr).await {
            Ok(stream) => {
                rport_client = Some(stream);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let mut rport_client = rport_client.expect("agent rportfwd listener never became reachable");
    rport_client.write_all(b"rportfwd-hello").await?;
    let mut echo = [0u8; 14];
    tokio::time::timeout(Duration::from_secs(10), rport_client.read_exact(&mut echo)).await??;
    assert_eq!(&echo, b"rportfwd-hello");

    let stop = client.stop_rportfwd(&status.forward_id).await?;
    assert!(!stop.running);

    socks_task.abort();
    fwd_task.abort();
    agent_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn team_features_rbac_audit_credentials_canary() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;
    let http_addr = http_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let operator_token = bootstrap.operator_token.clone();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let mut admin = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    // --- Bootstrap admin can create operators ---
    let watcher_name = format!("watcher-{}", uuid::Uuid::new_v4());
    let created = admin.create_operator(&watcher_name, "watcher").await?;
    let watcher_token = created.token.clone();
    let watcher_id = created.operator.as_ref().expect("operator").id.clone();
    assert_eq!(created.operator.as_ref().expect("operator").role, "watcher");
    let operators = admin.list_operators().await?;
    assert!(operators.iter().any(|op| op.id == watcher_id));

    // --- Watcher can read but cannot mutate ---
    let mut watcher = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        token: watcher_token,
        domain: "localhost".into(),
    })
    .await?;
    assert!(watcher.list_credentials().await.is_ok());
    assert!(
        watcher
            .add_credential("h", "u", "s", "password")
            .await
            .is_err(),
        "watcher must not add credentials"
    );
    assert!(
        watcher.create_operator("nope", "operator").await.is_err(),
        "watcher must not create operators"
    );

    // --- Admin stores a credential (audited) ---
    let credential = admin
        .add_credential("10.0.0.5", "administrator", "hunter2", "password")
        .await?;
    assert_eq!(credential.username, "administrator");
    let listed = watcher.list_credentials().await?;
    assert!(listed.iter().any(|item| item.host == "10.0.0.5"));

    // --- Loot round-trip ---
    let loot = admin
        .add_loot("notes.txt", b"engagement notes".to_vec(), "file")
        .await?;
    assert_eq!(loot.size, 16);
    let loot_list = watcher.list_loot().await?;
    assert!(loot_list.iter().any(|item| item.id == loot.id));

    // --- Canary + reaction rule, trigger via HTTP ---
    let canary = admin.create_canary("http", "honeytoken").await?;
    admin
        .add_reaction("canary_triggered", "log_and_alert")
        .await?;
    let rules = admin.list_reactions().await?;
    assert!(rules
        .iter()
        .any(|rule| rule.event_kind == "canary_triggered"));

    let canary_url = format!(
        "http://127.0.0.1:{}/canary/{}",
        http_addr.port(),
        canary.token
    );
    let response = reqwest::get(&canary_url).await?;
    assert!(response.status().is_success(), "canary trigger failed");

    // Trigger state persists.
    let canaries = admin.list_canaries().await?;
    let stored = canaries
        .iter()
        .find(|item| item.id == canary.id)
        .expect("canary");
    assert!(stored.triggered, "canary should be triggered");

    // --- Audit chain verifies after all actions ---
    let audit = admin.verify_audit().await?;
    assert!(audit.valid, "audit chain invalid: {}", audit.message);
    assert!(audit.entries >= 3, "expected several audit entries");

    // --- Admin deletes the watcher ---
    admin.delete_operator(&watcher_id).await?;

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_pivot_downstream_agent() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: http_listener.local_addr()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;
    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());

    // Upstream agent connects directly.
    let upstream_task = tokio::spawn(run_agent(AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token: enroll_token.clone(),
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    }));

    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;
    let upstream = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    // Pick a free port for the pivot bind on the upstream agent.
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let pivot_port = probe.local_addr()?.port();
    drop(probe);

    let status = client
        .start_rportfwd(
            &upstream.id,
            &format!("127.0.0.1:{pivot_port}"),
            &format!("127.0.0.1:{}", grpc_addr.port()),
        )
        .await?;
    assert!(status.running, "pivot failed to start: {}", status.message);

    // Downstream agent connects through the pivot (no direct route to server).
    let downstream_mark = prost_types::Timestamp::from(std::time::SystemTime::now());
    let downstream_task = tokio::spawn(run_agent(AgentConfig {
        endpoint: format!("https://127.0.0.1:{pivot_port}"),
        ca_pem,
        server_identity,
        enroll_token,
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    }));

    // Wait for the downstream session to register.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let downstream = loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let sessions = client.sessions().await?;
        let downstream = sessions
            .iter()
            .find(|session| {
                session.id != upstream.id && first_seen_after(session, &downstream_mark)
            })
            .cloned();
        if let Some(session) = downstream {
            break session;
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = client.stop_rportfwd(&status.forward_id).await;
            anyhow::bail!("downstream agent never registered through the pivot");
        }
    };

    // Task the downstream session through the tunneled connection.
    let result = client
        .run_task(
            &downstream.id,
            "shell",
            serde_json::json!({ "command": "echo pivot-downstream-ok" }),
        )
        .await?;
    assert_eq!(result.exit_code, 0);
    assert!(String::from_utf8_lossy(&result.output).contains("pivot-downstream-ok"));

    let _ = client.stop_rportfwd(&status.forward_id).await;
    upstream_task.abort();
    downstream_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_hop_pivot_chain_and_portscan() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: http_listener.local_addr()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;
    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());

    // Hop 1: an agent with a direct route to the teamserver.
    let hop1 = tokio::spawn(run_agent(AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token: enroll_token.clone(),
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    }));

    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;
    let session1 = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    // Pivot on hop 1: listener that dials the teamserver gRPC port.
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let hop1_port = probe.local_addr()?.port();
    drop(probe);
    let fwd1 = client
        .start_rportfwd(
            &session1.id,
            &format!("127.0.0.1:{hop1_port}"),
            &format!("127.0.0.1:{}", grpc_addr.port()),
        )
        .await?;
    assert!(fwd1.running, "hop1 pivot failed: {}", fwd1.message);

    // Hop 2: an agent that only reaches the teamserver through hop 1.
    let hop2_mark = prost_types::Timestamp::from(std::time::SystemTime::now());
    let hop2 = tokio::spawn(run_agent(AgentConfig {
        endpoint: format!("https://127.0.0.1:{hop1_port}"),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token: enroll_token.clone(),
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    }));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let session2 = loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let sessions = client.sessions().await?;
        if let Some(found) = sessions
            .iter()
            .find(|s| s.id != session1.id && first_seen_after(s, &hop2_mark))
            .cloned()
        {
            break found;
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("hop2 agent never registered through the first pivot");
        }
    };

    // Pivot on hop 2: its listener is only reachable from hop 2's network
    // position, and its traffic traverses hop 1 (multi-hop chain).
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let hop2_port = probe.local_addr()?.port();
    drop(probe);
    let fwd2 = client
        .start_rportfwd(
            &session2.id,
            &format!("127.0.0.1:{hop2_port}"),
            &format!("127.0.0.1:{}", grpc_addr.port()),
        )
        .await?;
    assert!(fwd2.running, "hop2 pivot failed: {}", fwd2.message);

    // Hop 3: an agent whose C2 path is hop3 -> hop2 -> hop1 -> teamserver.
    let hop3_mark = prost_types::Timestamp::from(std::time::SystemTime::now());
    let hop3 = tokio::spawn(run_agent(AgentConfig {
        endpoint: format!("https://127.0.0.1:{hop2_port}"),
        ca_pem,
        server_identity,
        enroll_token,
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    }));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let session3 = loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let sessions = client.sessions().await?;
        if let Some(found) = sessions
            .iter()
            .find(|s| s.id != session1.id && s.id != session2.id && first_seen_after(s, &hop3_mark))
            .cloned()
        {
            break found;
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("hop3 agent never registered through the pivot chain");
        }
    };

    // Task the deepest session: the result travels the full chain.
    let result = client
        .run_task(
            &session3.id,
            "shell",
            serde_json::json!({ "command": "echo multi-hop-ok" }),
        )
        .await?;
    assert_eq!(result.exit_code, 0, "hop3 task failed");
    assert!(String::from_utf8_lossy(&result.output).contains("multi-hop-ok"));

    // Pivot listing shows both hops with connection accounting.
    let forwards = client.list_rportfwds().await?;
    let listed1 = forwards
        .iter()
        .find(|f| f.forward_id == fwd1.forward_id)
        .expect("hop1 forward listed");
    let listed2 = forwards
        .iter()
        .find(|f| f.forward_id == fwd2.forward_id)
        .expect("hop2 forward listed");
    assert_eq!(listed1.transport, "tcp");
    assert!(
        listed1.connections >= 1,
        "hop1 must count hop2's connection"
    );
    assert!(
        listed2.connections >= 1,
        "hop2 must count hop3's connection"
    );

    // In-implant port scan sees the hop1 pivot listener from the agent.
    let result = client
        .run_task(
            &session3.id,
            "portscan",
            serde_json::json!({
                "target": "127.0.0.1",
                "ports": hop2_port.to_string(),
                "timeout_ms": 500,
            }),
        )
        .await?;
    assert_eq!(
        result.exit_code,
        0,
        "portscan failed: {}",
        String::from_utf8_lossy(&result.output)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.output)?;
    assert_eq!(report["open"][0]["port"], hop2_port);

    let _ = client.stop_rportfwd(&fwd2.forward_id).await;
    let _ = client.stop_rportfwd(&fwd1.forward_id).await;
    hop1.abort();
    hop2.abort();
    hop3.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_beacon_encrypted_communication() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    let tls = bootstrap.tls.clone();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    // Bind the QUIC endpoint on an ephemeral UDP port before starting the server.
    let quic_endpoint = shikra_server::quic::server_endpoint(
        &tls.server_cert_pem,
        &tls.server_key_pem,
        "127.0.0.1:0".parse()?,
    )?;
    let quic_addr = quic_endpoint.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: http_listener.local_addr()?,
        quic_addr,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            Some(quic_endpoint),
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;

    // QUIC beacon.
    let profile = shikra_transport::profile::C2Profile {
        poll_interval_secs: 1,
        jitter_secs: 0,
        ..Default::default()
    };

    let quic_agent = tokio::spawn(shikra_implant::run_quic_beacon(
        shikra_implant::QuicConfig {
            server_addr: quic_addr.to_string(),
            server_name: "localhost".into(),
            ca_pem: ca_pem.clone(),
            server_identity,
            enroll_token,
            profile,
            max_runtime_secs: Some(60),
        },
    ));

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;
    assert_eq!(
        session.kind,
        shikra_proto::v1::SessionKind::Beacon as i32,
        "QUIC session must be a beacon"
    );

    let result = client
        .run_task(
            &session.id,
            "shell",
            serde_json::json!({ "command": "echo quic-transport-ok" }),
        )
        .await?;
    assert_eq!(result.exit_code, 0, "QUIC task failed");
    assert!(String::from_utf8_lossy(&result.output).contains("quic-transport-ok"));

    quic_agent.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_beacon_encrypted_communication() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    // Bind the DNS endpoint on an ephemeral UDP port before starting the server.
    let dns_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let dns_addr = dns_socket.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: http_listener.local_addr()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners {
                dns: Some(dns_socket),
                wg: None,
            },
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;

    let profile = shikra_transport::profile::C2Profile {
        poll_interval_secs: 1,
        jitter_secs: 0,
        ..Default::default()
    };

    let dns_agent = tokio::spawn(shikra_implant::run_dns_beacon(shikra_implant::DnsConfig {
        server_addr: dns_addr.to_string(),
        zone: "dns.shikra".into(),
        server_identity,
        enroll_token,
        profile,
        max_runtime_secs: Some(60),
    }));

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    let session = wait_for_session(&mut client, Duration::from_secs(20)).await?;
    assert_eq!(
        session.kind,
        shikra_proto::v1::SessionKind::Beacon as i32,
        "DNS session must be a beacon"
    );

    let result = client
        .run_task(
            &session.id,
            "shell",
            serde_json::json!({ "command": "echo dns-transport-ok" }),
        )
        .await?;
    assert_eq!(result.exit_code, 0, "DNS task failed");
    assert!(String::from_utf8_lossy(&result.output).contains("dns-transport-ok"));

    dns_agent.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wireguard_beacon_encrypted_communication() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    // Provision (or load) the WireGuard identity before the server starts so
    // the client can pin the public key.
    let (_wg_private, wg_public) =
        shikra_transport::wg::load_or_create_server_identity(state_dir.path())?;
    let wg_public_bytes = *wg_public.as_bytes();

    let wg_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let wg_addr = wg_socket.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: http_listener.local_addr()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners {
                dns: None,
                wg: Some(wg_socket),
            },
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;

    let profile = shikra_transport::profile::C2Profile {
        poll_interval_secs: 1,
        jitter_secs: 0,
        ..Default::default()
    };

    let wg_agent = tokio::spawn(shikra_implant::run_wg_beacon(shikra_implant::WgConfig {
        server_addr: wg_addr.to_string(),
        server_public: wg_public_bytes,
        server_identity,
        enroll_token,
        profile,
        max_runtime_secs: Some(60),
    }));

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    let session = wait_for_session(&mut client, Duration::from_secs(20)).await?;
    assert_eq!(
        session.kind,
        shikra_proto::v1::SessionKind::Beacon as i32,
        "WireGuard session must be a beacon"
    );

    let result = client
        .run_task(
            &session.id,
            "shell",
            serde_json::json!({ "command": "echo wireguard-transport-ok" }),
        )
        .await?;
    assert_eq!(result.exit_code, 0, "WireGuard task failed");
    assert!(String::from_utf8_lossy(&result.output).contains("wireguard-transport-ok"));

    wg_agent.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_exploitation_task_surface() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let http_addr = http_listener.local_addr()?;
    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;

    let profiles =
        shikra_transport::profile::ProfileSet::single(shikra_transport::profile::C2Profile {
            poll_interval_secs: 1,
            jitter_secs: 0,
            ..Default::default()
        });

    let beacon_task = tokio::spawn(shikra_implant::run_beacon(shikra_implant::BeaconConfig {
        base_url: format!("http://127.0.0.1:{}", http_addr.port()),
        ca_pem: Some(ca_pem.clone()),
        server_identity,
        enroll_token,
        profiles,
        max_runtime_secs: Some(60),
    }));

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    // --- spawn/kill roundtrip on the host platform ---
    let sleep = if cfg!(unix) { "/bin/sleep" } else { "timeout" };
    let spawn = client
        .run_task(
            &session.id,
            "spawn",
            serde_json::json!({ "command": sleep, "args": ["30"], "hidden": true }),
        )
        .await?;
    assert_eq!(
        spawn.exit_code,
        0,
        "spawn failed: {}",
        String::from_utf8_lossy(&spawn.output)
    );

    // Extract the pid from "spawned pid <n>".
    let output = String::from_utf8_lossy(&spawn.output);
    let pid: u32 = output
        .trim()
        .rsplit(' ')
        .next()
        .and_then(|value| value.parse().ok())
        .expect("spawn output contains pid");

    let kill = client
        .run_task(&session.id, "kill", serde_json::json!({ "pid": pid }))
        .await?;
    assert_eq!(
        kill.exit_code,
        0,
        "kill failed: {}",
        String::from_utf8_lossy(&kill.output)
    );

    // --- Windows-only tasks must fail with a clear message on other hosts ---
    #[cfg(not(windows))]
    {
        let inject = client
            .run_task(
                &session.id,
                "inject",
                serde_json::json!({ "pid": 1, "shellcode": "AA==" }),
            )
            .await?;
        assert_ne!(inject.exit_code, 0);
        assert!(String::from_utf8_lossy(&inject.output).contains("Windows"));

        let assembly = client
            .run_task(
                &session.id,
                "execute_assembly",
                serde_json::json!({ "assembly": "AA==", "arguments": "" }),
            )
            .await?;
        assert_ne!(assembly.exit_code, 0);
    }

    beacon_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_rotation_and_staged_delivery() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;
    let http_addr = http_listener.local_addr()?;

    // Two profiles with distinct URIs force the beacon to rotate routes.
    let profiles = shikra_transport::profile::ProfileSet {
        profiles: vec![
            shikra_transport::profile::C2Profile {
                name: "alpha".into(),
                enroll_uri: "/alpha/enroll".into(),
                poll_uri: "/alpha/poll".into(),
                poll_interval_secs: 1,
                jitter_secs: 0,
                ..Default::default()
            },
            shikra_transport::profile::C2Profile {
                name: "bravo".into(),
                enroll_uri: "/bravo/enroll".into(),
                poll_uri: "/bravo/poll".into(),
                poll_interval_secs: 1,
                jitter_secs: 0,
                ..Default::default()
            },
        ],
    };
    std::fs::write(
        state_dir.path().join("profiles.json"),
        serde_json::to_string_pretty(&profiles)?,
    )?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;
    wait_for_port(http_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;

    let beacon_task = tokio::spawn(shikra_implant::run_beacon(shikra_implant::BeaconConfig {
        base_url: format!("http://127.0.0.1:{}", http_addr.port()),
        ca_pem: None,
        server_identity,
        enroll_token,
        profiles: profiles.clone(),
        max_runtime_secs: Some(60),
    }));

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    // Let a few poll cycles run so both profiles get exercised.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let result = client
        .run_task(
            &session.id,
            "shell",
            serde_json::json!({ "command": "echo rotation-ok" }),
        )
        .await?;
    assert_eq!(result.exit_code, 0, "rotating beacon task failed");
    assert!(String::from_utf8_lossy(&result.output).contains("rotation-ok"));

    // --- Staged delivery: host an encoded script and stage_run it ---
    #[cfg(unix)]
    {
        let marker = state_dir.path().join("stage-marker.txt");
        let script = format!("#!/bin/sh\necho staged > {}\n", marker.display());
        let key = "00112233445566778899aabbccddeeff";
        let encoded = shikra_implant::stager::encode_stage(key, script.as_bytes())?;
        std::fs::write(state_dir.path().join("hosted").join("test.stage"), &encoded)?;

        let stage_url = format!("http://127.0.0.1:{}/cdn/test.stage", http_addr.port());
        let result = client
            .run_task(
                &session.id,
                "stage_run",
                serde_json::json!({ "url": stage_url, "key": key }),
            )
            .await?;
        assert_eq!(
            result.exit_code,
            0,
            "stage_run failed: {}",
            String::from_utf8_lossy(&result.output)
        );

        // The staged script writes the marker asynchronously; poll briefly.
        let mut seen = false;
        for _ in 0..50 {
            if marker.exists() {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(seen, "staged script did not run (marker missing)");
    }

    beacon_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profiles_rpc_updates_live_http_routes() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;
    let http_addr = http_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let operator_token = bootstrap.operator_token.clone();
    drop(bootstrap);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;
    wait_for_port(http_addr).await?;

    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: format!("https://127.0.0.1:{}", grpc_addr.port()),
        ca_pem: load_ca_pem(state_dir.path())?,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    let initial = client.profiles().await?;
    assert_eq!(initial.len(), 1, "default profile set expected");
    assert_eq!(initial[0].name, "default");

    let custom = shikra_proto::v1::ProfileInfo {
        name: "edge".into(),
        user_agent: "curl/8.4.0".into(),
        enroll_uri: "/updates/v2/checkin".into(),
        poll_uri: "/updates/v2/task".into(),
        request_headers: Default::default(),
        response_headers: Default::default(),
        poll_interval_secs: 2,
        jitter_secs: 1,
    };
    client.set_profiles(vec![custom.clone()]).await?;

    let updated = client.profiles().await?;
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].user_agent, "curl/8.4.0");

    // The new route is served immediately; the previous default route is gone.
    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", http_addr.port());
    let new_route = http
        .post(format!("{base}/updates/v2/checkin"))
        .body(vec![0u8; 4])
        .send()
        .await?;
    assert_eq!(new_route.status(), reqwest::StatusCode::BAD_REQUEST);
    let old_route = http
        .post(format!("{base}/api/v1/enroll"))
        .body(vec![0u8; 4])
        .send()
        .await?;
    assert_eq!(old_route.status(), reqwest::StatusCode::NOT_FOUND);

    // Invalid updates are rejected without touching the live set.
    let invalid = shikra_proto::v1::ProfileInfo {
        enroll_uri: "no-slash".into(),
        ..custom
    };
    assert!(client.set_profiles(vec![invalid]).await.is_err());
    let still = client.profiles().await?;
    assert_eq!(still[0].enroll_uri, "/updates/v2/checkin");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listeners_start_and_stop_at_runtime() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: "127.0.0.1:0".parse()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let operator_token = bootstrap.operator_token.clone();
    drop(bootstrap);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    // No beacon listener is bound at boot: the HTTP listener is omitted.
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            None,
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: format!("https://127.0.0.1:{}", grpc_addr.port()),
        ca_pem: load_ca_pem(state_dir.path())?,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    assert!(client.listeners().await?.is_empty());

    // Port 0 asks the server to pick a free port and report it back.
    let http = client.start_listener("http", "127.0.0.1:0", "").await?;
    assert_eq!(http.kind, "http");
    let http_addr: std::net::SocketAddr = http.addr.parse()?;
    let base = format!("http://{http_addr}");

    let web = reqwest::Client::new();
    let response = web
        .post(format!("{base}/api/v1/enroll"))
        .body(vec![0u8; 4])
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    // A second listener on the same address must fail cleanly.
    let conflict = client
        .start_listener("http", &http_addr.to_string(), "")
        .await;
    assert!(conflict.is_err(), "duplicate bind must be rejected");

    // Unsupported kinds are rejected before any bind is attempted.
    assert!(client
        .start_listener("tcp", "127.0.0.1:0", "")
        .await
        .is_err());

    let running = client.listeners().await?;
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].addr, http_addr.to_string());

    client.stop_listener(&http.id).await?;
    assert!(client.listeners().await?.is_empty());
    assert!(client.stop_listener(&http.id).await.is_err());

    // The port is released after stopping.
    let stopped = web
        .post(format!("{base}/api/v1/enroll"))
        .body(vec![0u8; 4])
        .send()
        .await;
    assert!(stopped.is_err(), "listener should be gone after stop");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chat_events_and_webhook_rpcs() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: "127.0.0.1:0".parse()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let operator_token = bootstrap.operator_token.clone();
    drop(bootstrap);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            None,
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: format!("https://127.0.0.1:{}", grpc_addr.port()),
        ca_pem: load_ca_pem(state_dir.path())?,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    // Chat round-trip. The chat log is shared and persists across runs, so
    // assert on a unique marker instead of an empty table.
    let marker = format!("e2e-chat-{}", uuid::Uuid::new_v4());
    client.send_chat(&marker).await?;
    let messages = client.chat(500).await?;
    let stored = messages
        .iter()
        .find(|message| message.message == marker)
        .expect("marker message persisted");
    assert!(!stored.operator.is_empty());
    assert!(client.send_chat("   ").await.is_err());

    // Event feed answers even when empty.
    let _events = client.events(100).await?;

    // Webhook validation and persistence.
    assert!(client
        .set_webhook("https://example.com/hook")
        .await
        .is_err());
    client
        .set_webhook("https://discord.com/api/webhooks/123456789/abcdef")
        .await?;
    assert_eq!(
        client.webhook().await?,
        "https://discord.com/api/webhooks/123456789/abcdef"
    );
    assert!(
        std::fs::read_to_string(state_dir.path().join("webhook.json"))?.contains("discord.com")
    );
    client.set_webhook("").await?;
    assert!(client.webhook().await?.is_empty());

    // Session UI updates reject invalid colors before touching the registry.
    let bad_color = client
        .set_session_ui("00000000-0000-0000-0000-000000000000", "red", "dead")
        .await;
    assert!(bad_color.is_err());

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn task_cancellation_stops_long_shell() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: "127.0.0.1:0".parse()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            None,
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;
    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());

    let agent_task = tokio::spawn(shikra_implant::run_agent(shikra_implant::AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token,
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    }));

    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;
    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    // Submit a long shell in the background and cancel it mid-flight.
    let mut submitter = client.clone();
    let session_id = session.id.clone();
    let submit = tokio::spawn(async move {
        submitter
            .run_task(
                &session_id,
                "shell",
                serde_json::json!({ "command": "sleep 30", "timeout_secs": 60 }),
            )
            .await
    });

    let mut target_task = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let tasks = client.list_tasks(Some(&session.id), 20).await?;
        if let Some(task) = tasks
            .into_iter()
            .find(|task| task.command == "shell" && matches!(task.state, 2 | 3))
        {
            target_task = Some(task);
            break;
        }
    }
    let task = target_task.expect("shell task should be dispatched");
    client.cancel_task(&session.id, &task.id).await?;

    let result = tokio::time::timeout(Duration::from_secs(10), submit)
        .await
        .expect("cancelled task should return promptly")
        .expect("submit task join")
        .expect("submit result");
    assert_eq!(
        shikra_proto::v1::TaskState::try_from(result.state).unwrap(),
        shikra_proto::v1::TaskState::Cancelled,
        "cancelled task must report Cancelled"
    );

    // Persisted state agrees.
    let tasks = client.list_tasks(Some(&session.id), 20).await?;
    let stored = tasks
        .iter()
        .find(|row| row.id == task.id)
        .expect("task row");
    assert_eq!(
        shikra_proto::v1::TaskState::try_from(stored.state).unwrap(),
        shikra_proto::v1::TaskState::Cancelled,
        "DB task state should be cancelled"
    );

    agent_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn smb_pipe_lateral_child_checks_in_through_parent() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let socket_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: "127.0.0.1:0".parse()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            None,
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;
    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());

    // Parent agent with a direct route to the teamserver.
    let parent_config = AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token: enroll_token.clone(),
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(90),
    };
    let parent_task = tokio::spawn(run_agent(parent_config));

    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;
    let parent = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    // Parent relays an operator-chosen pipe to the teamserver's own gRPC port.
    let socket_path = socket_dir.path().join("shikra-smb.sock");
    let socket_path = socket_path.to_string_lossy().to_string();
    client
        .start_rportfwd_transport(
            &parent.id,
            &socket_path,
            &format!("127.0.0.1:{}", grpc_addr.port()),
            "pipe",
        )
        .await?;

    // Child agent reaches the teamserver only through the parent's pipe.
    let child_config = AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token: enroll_token.clone(),
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(90),
    };
    let child_mark = prost_types::Timestamp::from(std::time::SystemTime::now());
    let child_task = tokio::spawn(shikra_implant::run_agent_piped(
        child_config,
        Some(socket_path.clone()),
    ));

    // Wait for the child session; it appears exactly like a direct one.
    let mut child = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sessions = client.sessions().await?;
        if let Some(found) = sessions
            .iter()
            .find(|session| {
                session.id != parent.id
                    && session.status == 1
                    && first_seen_after(session, &child_mark)
            })
            .cloned()
        {
            child = Some(found);
            break;
        }
    }
    let child = child.expect("child session should check in through the parent pipe");

    // End-to-end task over the pipe chain.
    let result = client
        .run_task(&child.id, "echo", serde_json::json!("pipe-child"))
        .await?;
    assert_eq!(result.exit_code, 0);
    assert_eq!(String::from_utf8_lossy(&result.output), "pipe-child");

    parent_task.abort();
    child_task.abort();
    let _ = std::fs::remove_file(&socket_path);
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_agent_bridge_round_trip() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;
    let http_addr = http_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let relay_token = bootstrap.relay_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    drop(bootstrap);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;
    wait_for_port(http_addr).await?;

    let base = format!("http://127.0.0.1:{}", http_addr.port());
    let web = reqwest::Client::new();

    // Registration requires the relay token.
    let unauthorized = web
        .post(format!("{base}/api/v1/external/register"))
        .json(&serde_json::json!({ "hostname": "ext" }))
        .send()
        .await?;
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

    let registration: serde_json::Value = web
        .post(format!("{base}/api/v1/external/register"))
        .bearer_auth(&relay_token)
        .json(&serde_json::json!({
            "hostname": "ext-host",
            "username": "ext-user",
            "platform": "linux",
            "architecture": "x86_64",
            "process_name": "external-agent.py",
        }))
        .send()
        .await?
        .json()
        .await?;
    let session_id = registration["session_id"].as_str().unwrap().to_string();
    let session_token = registration["session_token"].as_str().unwrap().to_string();
    assert!(!session_id.is_empty() && !session_token.is_empty());

    // The external agent shows up as a session.
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: format!("https://127.0.0.1:{}", grpc_addr.port()),
        ca_pem: load_ca_pem(state_dir.path())?,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;
    let mut external = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(found) = client
            .sessions()
            .await?
            .into_iter()
            .find(|session| session.id == session_id)
        {
            external = Some(found);
            break;
        }
    }
    let external = external.expect("external session registered");
    assert_eq!(
        shikra_proto::v1::SessionKind::try_from(external.kind).unwrap(),
        shikra_proto::v1::SessionKind::External
    );

    // Submit a task and serve it through the external endpoints.
    let mut submitter = client.clone();
    let submit_session = session_id.clone();
    let submit = tokio::spawn(async move {
        submitter
            .run_task(&submit_session, "echo", serde_json::json!("ext-hello"))
            .await
    });

    let mut task_id = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let batch: serde_json::Value = web
            .get(format!("{base}/api/v1/external/{session_id}/tasks"))
            .bearer_auth(&session_token)
            .send()
            .await?
            .json()
            .await?;
        if let Some(task) = batch["tasks"].as_array().and_then(|tasks| tasks.first()) {
            task_id = task["task_id"].as_str().map(str::to_string);
            break;
        }
    }
    let task_id = task_id.expect("external agent should receive the task");

    // Wrong session tokens are rejected.
    let rejected = web
        .get(format!("{base}/api/v1/external/{session_id}/tasks"))
        .bearer_auth("wrong")
        .send()
        .await?;
    assert_eq!(rejected.status(), reqwest::StatusCode::UNAUTHORIZED);

    let posted = web
        .post(format!("{base}/api/v1/external/{session_id}/results"))
        .bearer_auth(&session_token)
        .json(&serde_json::json!([{
            "task_id": task_id,
            "exit_code": 0,
            "stdout_hex": shikra_transport::tls::hex_encode(b"ext-hello"),
            "stderr": "",
        }]))
        .send()
        .await?;
    assert!(posted.status().is_success());

    let result = tokio::time::timeout(Duration::from_secs(10), submit)
        .await
        .expect("task result should arrive")
        .expect("submit join")
        .expect("submit result");
    assert_eq!(result.exit_code, 0);
    assert_eq!(String::from_utf8_lossy(&result.output), "ext-hello");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resumable_download_continues_from_partial_file() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let work_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr: "127.0.0.1:0".parse()?,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            None,
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;
    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());

    let agent_task = tokio::spawn(run_agent(AgentConfig {
        endpoint: endpoint.clone(),
        ca_pem: ca_pem.clone(),
        server_identity,
        enroll_token,
        domain: "localhost".into(),
        heartbeat_secs: 1,
        jitter_secs: 0,
        max_runtime_secs: Some(60),
    }));
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;
    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    let source: Vec<u8> = (0..2_500_000usize).map(|i| (i % 251) as u8).collect();
    let local = work_dir.path().join("source.bin");
    tokio::fs::write(&local, &source).await?;
    let remote = format!("/tmp/shikra-resume-{}.bin", std::process::id());
    client.upload(&session.id, &local, &remote).await?;

    // Simulate an interrupted transfer: only the first ~1.2 MiB exist locally.
    let dest = work_dir.path().join("dest.bin");
    tokio::fs::write(&dest, &source[..1_200_000]).await?;
    let total = client
        .download_resumable(&session.id, &remote, &dest, true)
        .await?;
    assert_eq!(total, source.len() as u64);
    assert_eq!(
        tokio::fs::read(&dest).await?,
        source,
        "resumed file must match"
    );

    // A fresh download writes the same content.
    let fresh = work_dir.path().join("fresh.bin");
    client
        .download_resumable(&session.id, &remote, &fresh, true)
        .await?;
    assert_eq!(tokio::fs::read(&fresh).await?, source);

    let _ = tokio::fs::remove_file(&remote).await;
    agent_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extension_registry_signed_install_and_push() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;
    let http_addr = http_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    let server_identity_hex = bootstrap.server_identity_hex();
    let armory_public = bootstrap.armory_public;
    drop(bootstrap);
    let ca_pem = load_ca_pem(state_dir.path())?;

    // Recover the armory signing key so the test can sign packages.
    let armory_seed_hex = std::fs::read_to_string(state_dir.path().join("armory.key"))?
        .trim()
        .to_string();
    let armory_seed_bytes = shikra_transport::tls::hex_decode(&armory_seed_hex)?;
    let armory_seed: [u8; 32] = armory_seed_bytes.as_slice().try_into()?;
    let armory_identity = shikra_crypto::signing::Identity::from_seed(&armory_seed);
    assert_eq!(armory_identity.public_key_bytes(), armory_public);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;

    let identity_bytes = shikra_transport::tls::hex_decode(&server_identity_hex)?;
    let server_identity: [u8; 32] = identity_bytes.as_slice().try_into()?;

    let profiles =
        shikra_transport::profile::ProfileSet::single(shikra_transport::profile::C2Profile {
            poll_interval_secs: 1,
            jitter_secs: 0,
            ..Default::default()
        });
    let beacon_task = tokio::spawn(shikra_implant::run_beacon(shikra_implant::BeaconConfig {
        base_url: format!("http://127.0.0.1:{}", http_addr.port()),
        ca_pem: None,
        server_identity,
        enroll_token,
        profiles,
        max_runtime_secs: Some(60),
    }));

    let endpoint = format!("https://127.0.0.1:{}", grpc_addr.port());
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint,
        ca_pem,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;

    let session = wait_for_session(&mut client, Duration::from_secs(15)).await?;

    // --- Pack a WASM extension signed with the armory key ---
    let wat = r#"
    (module
      (import "env" "host_output" (func $host_output (param i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 1024) "registry-ext-ok")
      (func (export "alloc") (param i32) (result i32) (i32.const 2048))
      (func (export "run") (param i32 i32) (result i32)
        (call $host_output (i32.const 1024) (i32.const 15))
        (i32.const 0)))
    "#;
    let wasm = wat::parse_str(wat)?;
    let manifest = shikra_transport::extension::ExtensionManifest {
        name: "registry-echo".into(),
        version: "1.0.0".into(),
        kind: shikra_transport::extension::ExtensionKind::Wasm,
        platform: shikra_transport::extension::ExtensionPlatform::Any,
        architecture: "any".into(),
        description: "e2e extension".into(),
        sha256: String::new(),
        size: 0,
    };
    let package = shikra_transport::extension::ExtensionPackage::build(
        manifest.clone(),
        &wasm,
        &armory_identity,
    )?;
    let package_json = package.to_json()?;

    // --- Install and list ---
    let info = client.install_extension(package_json.clone()).await?;
    assert_eq!(info.name, "registry-echo");
    assert_eq!(info.kind, "wasm");
    assert_eq!(
        info.signer,
        shikra_transport::tls::hex_encode(&armory_public)
    );

    let listed = client.list_extensions().await?;
    assert!(listed.iter().any(|item| item.id == info.id));

    // --- Fetch returns the exact payload ---
    let fetched = client.fetch_extension(&info.id).await?;
    assert_eq!(fetched.payload, wasm);
    let by_name = client
        .fetch_extension_by_name("registry-echo", "macos")
        .await?;
    assert_eq!(by_name.payload, wasm);

    // --- Tampered package is rejected ---
    let mut tampered = package.clone();
    let mut payload = wasm.clone();
    payload[0] ^= 0x01;
    tampered.payload_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&payload)
    };
    let tampered_json = tampered.to_json()?;
    assert!(
        client.install_extension(tampered_json).await.is_err(),
        "tampered package must be rejected"
    );

    // --- Package signed by the wrong key is rejected ---
    let rogue = shikra_crypto::signing::Identity::generate();
    let rogue_package =
        shikra_transport::extension::ExtensionPackage::build(manifest, &wasm, &rogue)?;
    assert!(
        client
            .install_extension(rogue_package.to_json()?)
            .await
            .is_err(),
        "package signed by an untrusted key must be rejected"
    );

    // --- Push to the target: fetch + wasm_load + wasm_run ---
    let result = client
        .submit_task(
            &session.id,
            "wasm_load",
            serde_json::json!({ "name": "registry-echo" }),
            fetched.payload.clone(),
        )
        .await?;
    assert_eq!(
        result[0].exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&result[0].output)
    );

    let result = client
        .run_task(
            &session.id,
            "wasm_run",
            serde_json::json!({ "name": "registry-echo", "args": "" }),
        )
        .await?;
    assert_eq!(
        result.exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&result.output)
    );
    assert!(String::from_utf8_lossy(&result.output).contains("registry-ext-ok"));

    // --- Delete removes it from the registry ---
    client.delete_extension(&info.id).await?;
    let listed = client.list_extensions().await?;
    assert!(!listed.iter().any(|item| item.id == info.id));

    beacon_task.abort();
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrollment_is_rate_limited_and_audited() -> anyhow::Result<()> {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping e2e test: SHIKRA_TEST_DATABASE_URL/DATABASE_URL not set");
        return Ok(());
    };

    let state_dir = tempfile::tempdir()?;
    let grpc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let grpc_addr = grpc_listener.local_addr()?;
    let http_addr = http_listener.local_addr()?;

    let config = ServerConfig {
        grpc_addr,
        health_addr: health_listener.local_addr()?,
        http_addr,
        quic_addr: "127.0.0.1:0".parse()?,
        dns_addr: "127.0.0.1:0".parse()?,
        wg_addr: "127.0.0.1:0".parse()?,
        dns_zone: "dns.shikra".into(),
        database_url: database_url.clone(),
        state_dir: state_dir.path().to_path_buf(),
        log_format: LogFormat::Text,
    };

    let bootstrap = shikra_server::bootstrap::bootstrap(state_dir.path())?;
    let enroll_token = bootstrap.enroll_token.clone();
    let operator_token = bootstrap.operator_token.clone();
    drop(bootstrap);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        shikra_server::run_with_listeners(
            config,
            grpc_listener,
            health_listener,
            Some(http_listener),
            None,
            shikra_server::UdpListeners::default(),
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
    });
    wait_for_port(grpc_addr).await?;
    wait_for_port(http_addr).await?;

    // 30 attempts fit the per-peer budget; the 31st must be throttled. All
    // use an invalid token so none of them registers a session.
    let enroll_url = format!("http://127.0.0.1:{}/api/v1/enroll", http_addr.port());
    let client = reqwest::Client::new();
    let mut throttled = false;
    for attempt in 0..31 {
        let request = shikra_proto::v1::CheckInRequest {
            identity_public: vec![0u8; 32],
            kex_public: vec![0u8; 32],
            identity_signature: vec![0u8; 64],
            hostname: "rate-limit-test".into(),
            username: String::new(),
            platform: 0,
            architecture: 0,
            process_name: String::new(),
            kind: shikra_proto::v1::SessionKind::Beacon as i32,
            enrollment_token: "wrong-token".into(),
            killdate_unix: 0,
            working_hours: String::new(),
        };
        use prost::Message;
        let response = client
            .post(&enroll_url)
            .body(request.encode_to_vec())
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            assert!(attempt >= 30, "throttled before exhausting the budget");
            throttled = true;
            break;
        }
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "attempt {attempt} expected 401"
        );
    }
    assert!(throttled, "enrollment was never rate limited");

    // The operator control plane stays reachable while enrollment is throttled.
    let mut client = shikra_client::OperatorClient::connect(&shikra_client::ClientConfig {
        endpoint: format!("https://127.0.0.1:{}", grpc_addr.port()),
        ca_pem: load_ca_pem(state_dir.path())?,
        token: operator_token,
        domain: "localhost".into(),
    })
    .await?;
    assert!(!client.version().await?.is_empty());

    // Enrollment rejections are still recorded as events for detection.
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE kind IN ('enrollment_rejected', 'enrollment_rate_limited')",
    )
    .fetch_one(&sqlx::PgPool::connect(&database_url).await?)
    .await?;
    assert!(events >= 1, "expected enrollment rejection events");

    // A valid token is accepted after the throttle clears only once its
    // bucket resets; the shared unknown bucket resets on a successful enroll,
    // so verify a fresh peer (different server) is unaffected is out of scope.
    // Instead confirm the limiter budgets are per-key via the unit tests.
    drop(enroll_token);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}
