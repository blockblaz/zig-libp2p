//! rust-libp2p side of the zig-libp2p QUIC interop runner (Phase B5).
//!
//! Same env contract as the go-libp2p and zig impls so the matrix runner
//! can drop this binary into any (server, client) slot.
//!
//! Environment variables:
//!
//!   ROLE        — "server" | "client"
//!   TESTCASE    — "handshake" | "ping" | "gossipsub" | "reqresp"
//!   LISTEN_PORT — UDP port on which the server listens (default 4001)
//!   SERVER_HOST — IPv4 to dial (default 127.0.0.1)
//!   SERVER_PORT — UDP port to dial (default 4001)
//!   DEADLINE_MS — overall test deadline (default 30000)
//!   SEED_HEX    — 32-byte hex; deterministic ed25519 identity.
//!   REMOTE_PEER_ID — client only; required for ping/gossipsub/reqresp.
//!
//! gossipsub-specific:
//!   GS_TOPIC       — pubsub topic (default "/interop/b3")
//!   GS_COUNT       — number of messages the server publishes (default 5)
//!   GS_PAYLOAD_LEN — bytes per message (default 64)
//!
//! reqresp-specific:
//!   RR_PAYLOAD_LEN — bytes per request+response (default 256)
//!   Protocol id: /interop/b4/echo/1.0.0
//!
//! Stdout includes `rust_libp2p_peer_id: peer_id=<base58btc>` on both
//! roles for capture by the matrix runner.

use std::collections::HashSet;
use std::env;
use std::time::Duration;

use futures::stream::StreamExt;
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::identity;
use libp2p::ping;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};

// ── env helpers ────────────────────────────────────────────────────────────

fn env_or(key: &str, fallback: &str) -> String {
    env::var(key).unwrap_or_else(|_| fallback.to_string())
}

fn env_int<T: std::str::FromStr>(key: &str, fallback: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

// ── B4 reqresp protocol ───────────────────────────────────────────────────
// Pinned identifier — must match the zig + go impls byte-for-byte.

const REQRESP_PROTOCOL: &str = "/interop/b4/echo/1.0.0";

#[derive(Clone, Debug, Default)]
struct EchoCodec;

#[async_trait::async_trait]
impl request_response::Codec for EchoCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T: futures::AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request> {
        use futures::AsyncReadExt;
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn read_response<T: futures::AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response> {
        use futures::AsyncReadExt;
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn write_request<T: futures::AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()> {
        use futures::AsyncWriteExt;
        io.write_all(&req).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T: futures::AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()> {
        use futures::AsyncWriteExt;
        io.write_all(&res).await?;
        io.close().await?;
        Ok(())
    }
}

// ── network behaviour ─────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct Behaviour {
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
    reqresp: request_response::Behaviour<EchoCodec>,
}

impl Behaviour {
    fn new(local_key: &identity::Keypair) -> Result<Self, Box<dyn std::error::Error>> {
        let gs_cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_millis(500))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()?;
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gs_cfg,
        )?;
        let reqresp = request_response::Behaviour::new(
            std::iter::once((
                libp2p::StreamProtocol::new(REQRESP_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default(),
        );
        Ok(Behaviour {
            ping: ping::Behaviour::default(),
            gossipsub,
            reqresp,
        })
    }
}

// ── identity / swarm construction ─────────────────────────────────────────

fn load_identity() -> Result<identity::Keypair, Box<dyn std::error::Error>> {
    if let Ok(seed_hex) = env::var("SEED_HEX") {
        let seed = hex::decode(seed_hex)?;
        if seed.len() != 32 {
            return Err(format!("SEED_HEX must be 32 bytes, got {}", seed.len()).into());
        }
        let kp = identity::ed25519::Keypair::from(identity::ed25519::SecretKey::try_from_bytes(
            &mut seed.clone()[..32].try_into().map(|a: [u8; 32]| a)?,
        )?);
        Ok(identity::Keypair::from(kp))
    } else {
        Ok(identity::Keypair::generate_ed25519())
    }
}

fn build_swarm() -> Result<Swarm<Behaviour>, Box<dyn std::error::Error>> {
    let local_key = load_identity()?;
    let local_peer = PeerId::from(local_key.public());
    println!("rust_libp2p_peer_id: peer_id={}", local_peer);

    let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| Behaviour::new(key).expect("behaviour"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    Ok(swarm)
}

// ── main / dispatch ───────────────────────────────────────────────────────

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::process::ExitCode {
    // Wire RUST_LOG / RUST_LOG_FILTER through tracing-subscriber so quinn /
    // libp2p-tls errors surface in cross-impl debugging. Default off.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let role = env_or("ROLE", "server");
    let testcase = env_or("TESTCASE", "handshake");
    let deadline_ms: u64 = env_int("DEADLINE_MS", 30_000);

    let result = tokio::time::timeout(
        Duration::from_millis(deadline_ms),
        run(&role, &testcase),
    )
    .await;

    match result {
        Ok(Ok(code)) => std::process::ExitCode::from(code),
        Ok(Err(e)) => {
            eprintln!("rust_libp2p_interop: {}", e);
            std::process::ExitCode::from(1)
        }
        Err(_) => {
            eprintln!("rust_libp2p_interop: deadline exceeded ({}ms)", deadline_ms);
            std::process::ExitCode::from(1)
        }
    }
}

async fn run(role: &str, testcase: &str) -> Result<u8, Box<dyn std::error::Error>> {
    match role {
        "server" => run_server(testcase).await,
        "client" => run_client(testcase).await,
        _ => Err(format!("unknown ROLE={}", role).into()),
    }
}

async fn run_server(testcase: &str) -> Result<u8, Box<dyn std::error::Error>> {
    let port: u16 = env_int("LISTEN_PORT", 4001);
    let mut swarm = build_swarm()?;
    let listen: Multiaddr = format!("/ip4/0.0.0.0/udp/{port}/quic-v1").parse()?;
    swarm.listen_on(listen)?;
    println!(
        "rust_libp2p_interop[server]: listening udp/{port} peer={}",
        swarm.local_peer_id()
    );

    match testcase {
        "handshake" => server_handshake(&mut swarm).await,
        "ping" => server_ping(&mut swarm).await,
        "gossipsub" => server_gossipsub(&mut swarm).await,
        "reqresp" => server_reqresp(&mut swarm).await,
        _ => Err(format!("unknown TESTCASE={}", testcase).into()),
    }
}

async fn run_client(testcase: &str) -> Result<u8, Box<dyn std::error::Error>> {
    let host = env_or("SERVER_HOST", "127.0.0.1");
    let port: u16 = env_int("SERVER_PORT", 4001);
    let remote_pid: PeerId = env::var("REMOTE_PEER_ID")
        .map_err(|_| "REMOTE_PEER_ID is required for client role")?
        .parse()?;

    let mut swarm = build_swarm()?;
    let target: Multiaddr = format!("/ip4/{host}/udp/{port}/quic-v1/p2p/{remote_pid}").parse()?;
    swarm.dial(target.clone())?;
    println!("rust_libp2p_interop[client]: dialing {target}");
    wait_connected(&mut swarm, remote_pid).await?;
    println!("rust_libp2p_interop[client]: connected");

    match testcase {
        "handshake" => {
            println!("rust_libp2p_interop[client]: handshake ok");
            Ok(0)
        }
        "ping" => client_ping(&mut swarm).await,
        "gossipsub" => client_gossipsub(&mut swarm).await,
        "reqresp" => client_reqresp(&mut swarm, remote_pid).await,
        _ => Err(format!("unknown TESTCASE={}", testcase).into()),
    }
}

async fn wait_connected(
    swarm: &mut Swarm<Behaviour>,
    remote: PeerId,
) -> Result<(), Box<dyn std::error::Error>> {
    while let Some(event) = swarm.next().await {
        if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
            if peer_id == remote {
                return Ok(());
            }
        }
    }
    Err("swarm stream ended before connection".into())
}

async fn wait_first_conn(
    swarm: &mut Swarm<Behaviour>,
) -> Result<PeerId, Box<dyn std::error::Error>> {
    while let Some(event) = swarm.next().await {
        if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
            return Ok(peer_id);
        }
    }
    Err("swarm stream ended before any connection".into())
}

// ── handshake ────────────────────────────────────────────────────────────

async fn server_handshake(swarm: &mut Swarm<Behaviour>) -> Result<u8, Box<dyn std::error::Error>> {
    let _ = wait_first_conn(swarm).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("rust_libp2p_interop[server]: handshake ok");
    Ok(0)
}

// ── ping ─────────────────────────────────────────────────────────────────

async fn server_ping(swarm: &mut Swarm<Behaviour>) -> Result<u8, Box<dyn std::error::Error>> {
    // libp2p::ping::Behaviour auto-replies to inbound pings. Wait for the
    // first event indicating a round-trip then exit.
    let _ = wait_first_conn(swarm).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => break,
            event = swarm.next() => {
                if let Some(SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
                    result: Ok(_), ..
                }))) = event {
                    println!("rust_libp2p_interop[server]: ping ok");
                    return Ok(0);
                }
            }
        }
    }
    Err("ping deadline".into())
}

async fn client_ping(swarm: &mut Swarm<Behaviour>) -> Result<u8, Box<dyn std::error::Error>> {
    while let Some(event) = swarm.next().await {
        if let SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
            result: Ok(rtt), ..
        })) = event
        {
            println!("rust_libp2p_interop[client]: ping ok rtt={:?}", rtt);
            return Ok(0);
        }
    }
    Err("ping client stream ended".into())
}

// ── gossipsub ────────────────────────────────────────────────────────────

fn gs_topic() -> String { env_or("GS_TOPIC", "/interop/b3") }
fn gs_count() -> usize { env_int("GS_COUNT", 5) }
fn gs_payload_len() -> usize { env_int("GS_PAYLOAD_LEN", 64) }

fn gs_payload(idx: usize, length: usize) -> Vec<u8> {
    let mut out = vec![0x2A; length];
    let header = format!("msg-{:05}:", idx).into_bytes();
    let copy_len = std::cmp::min(header.len(), length);
    out[..copy_len].copy_from_slice(&header[..copy_len]);
    out
}

async fn server_gossipsub(swarm: &mut Swarm<Behaviour>) -> Result<u8, Box<dyn std::error::Error>> {
    let topic = IdentTopic::new(gs_topic());
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    let _ = wait_first_conn(swarm).await?;
    // Let the mesh form.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let count = gs_count();
    let plen = gs_payload_len();
    for i in 0..count {
        let payload = gs_payload(i, plen);
        // Drive the swarm so backpressure events get processed between
        // publishes; otherwise large bursts can hit the per-peer queue.
        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload) {
            return Err(format!("publish #{i}: {e:?}").into());
        }
        // Quick yield so the swarm task can run.
        tokio::task::yield_now().await;
    }
    println!(
        "rust_libp2p_interop[server]: gossipsub published {} msgs on {:?}",
        count,
        gs_topic()
    );
    // Stay alive long enough for delivery.
    let drain_until = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(drain_until) => break,
            _ = swarm.next() => {}
        }
    }
    println!("rust_libp2p_interop[server]: gossipsub ok");
    Ok(0)
}

async fn client_gossipsub(swarm: &mut Swarm<Behaviour>) -> Result<u8, Box<dyn std::error::Error>> {
    let topic = IdentTopic::new(gs_topic());
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    let count = gs_count();
    let plen = gs_payload_len();
    let want: HashSet<Vec<u8>> = (0..count).map(|i| gs_payload(i, plen)).collect();
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(count);

    while seen.len() < count {
        match swarm.next().await {
            Some(SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                gossipsub::Event::Message { message, .. },
            ))) => {
                if want.contains(&message.data) {
                    seen.insert(message.data);
                } else {
                    eprintln!(
                        "rust_libp2p_interop[client]: gossipsub unexpected msg len={}",
                        message.data.len()
                    );
                }
            }
            Some(_) => {}
            None => return Err("swarm stream ended".into()),
        }
    }
    println!(
        "rust_libp2p_interop[client]: gossipsub got {}/{} msgs",
        seen.len(),
        count
    );
    println!("rust_libp2p_interop[client]: gossipsub ok");
    Ok(0)
}

// ── reqresp ──────────────────────────────────────────────────────────────

fn rr_payload_len() -> usize { env_int("RR_PAYLOAD_LEN", 256) }

fn rr_request_payload(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i & 0xff) as u8).collect()
}

async fn server_reqresp(swarm: &mut Swarm<Behaviour>) -> Result<u8, Box<dyn std::error::Error>> {
    let _ = wait_first_conn(swarm).await?;
    let plen = rr_payload_len();
    while let Some(event) = swarm.next().await {
        if let SwarmEvent::Behaviour(BehaviourEvent::Reqresp(
            request_response::Event::Message {
                message: request_response::Message::Request {
                    request, channel, ..
                },
                ..
            },
        )) = event
        {
            if request.len() != plen {
                return Err(format!("reqresp: got {} bytes want {}", request.len(), plen).into());
            }
            swarm
                .behaviour_mut()
                .reqresp
                .send_response(channel, request)
                .map_err(|_| "send_response failed")?;
            println!("rust_libp2p_interop[server]: reqresp ok ({} bytes)", plen);
            // Drain a tick so the response is flushed before we return.
            tokio::time::sleep(Duration::from_millis(200)).await;
            return Ok(0);
        }
    }
    Err("reqresp server: no request received".into())
}

async fn client_reqresp(
    swarm: &mut Swarm<Behaviour>,
    remote: PeerId,
) -> Result<u8, Box<dyn std::error::Error>> {
    let plen = rr_payload_len();
    let req = rr_request_payload(plen);
    let _ = swarm
        .behaviour_mut()
        .reqresp
        .send_request(&remote, req.clone());

    while let Some(event) = swarm.next().await {
        if let SwarmEvent::Behaviour(BehaviourEvent::Reqresp(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                ..
            },
        )) = event
        {
            if response != req {
                return Err("reqresp client: payload mismatch".into());
            }
            println!("rust_libp2p_interop[client]: reqresp ok ({} bytes)", plen);
            return Ok(0);
        }
    }
    Err("reqresp client: no response received".into())
}

