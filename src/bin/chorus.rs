use chorus::config::{Config, FriendlyConfig};
use chorus::counting_stream::CountingStream;
use chorus::error::Error;
use chorus::globals::GLOBALS;
use chorus::ip::HashedPeer;
use std::env;
use std::fs::OpenOptions;
use std::io::Read;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Get args (config path)
    let mut args = env::args();
    if args.len() <= 1 {
        panic!("USAGE: chorus <config_path>");
    }
    let _ = args.next(); // ignore program name
    let config_path = args.next().unwrap();

    let config = chorus::load_config(&config_path)?;

    chorus::setup_logging(&config);

    // Log host name
    log::info!(target: "Server", "HOSTNAME = {}", config.hostname);

    let store = chorus::setup_store(&config)?;
    let _ = GLOBALS.store.set(store);

    // TLS setup
    let maybe_tls_acceptor = if config.use_tls {
        log::info!(target: "Server", "Using TLS");
        Some(chorus::tls::tls_acceptor(&config)?)
    } else {
        log::info!(target: "Server", "Not using TLS");
        None
    };

    // Bind listener to port
    let listener = TcpListener::bind((&*config.ip_address, config.port)).await?;
    log::info!(target: "Server", "Running on {}:{}", config.ip_address, config.port);

    // Store config into GLOBALS
    *GLOBALS.config.write() = config;

    let mut interrupt_signal = signal(SignalKind::interrupt())?;
    let mut quit_signal = signal(SignalKind::quit())?;
    let mut terminate_signal = signal(SignalKind::terminate())?;
    let mut hup_signal = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            // Exits gracefully upon exit-type signals
            v = interrupt_signal.recv() => if v.is_some() {
                log::info!(target: "Server", "SIGINT");
                break;
            },
            v = quit_signal.recv() => if v.is_some() {
                log::info!(target: "Server", "SIGQUIT");
                break;
            },
            v = terminate_signal.recv() => if v.is_some() {
                log::info!(target: "Server", "SIGTERM");
                break;
            },

            // Reload config on HUP
            v = hup_signal.recv() => if v.is_some() {
                log::info!(target: "Server", "SIGHUP: Reloading configuration");

                // Reload the config file
                let mut file = OpenOptions::new().read(true).open(config_path.clone())?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let friendly_config: FriendlyConfig = toml::from_str(&contents)?;
                let config: Config = friendly_config.into_config()?;

                *GLOBALS.config.write() = config;

                chorus::print_stats();
            },

            // Accepts network connections and spawn a task to serve each one
            v = listener.accept() => {
                let (mut tcp_stream, hashed_peer) = {
                    let (tcp_stream, peer_addr) = v?;
                    let hashed_peer = HashedPeer::new(peer_addr);
                    (tcp_stream, hashed_peer)
                };

                // Possibly IP block early
                if ! GLOBALS.config.read().chorus_is_behind_a_proxy
                    && GLOBALS.config.read().enable_ip_blocking
                {
                    let ip_data = chorus::get_ip_data(GLOBALS.store.get().unwrap(), hashed_peer.ip())?;
                    if ip_data.is_banned() {
                        log::debug!(target: "Client",
                                    "{}: Blocking reconnection until {}",
                                    hashed_peer.ip(),
                                    ip_data.ban_until);
                        let _ = tcp_stream.shutdown().await;
                        continue;
                    }
                }

                let counting_stream = CountingStream(tcp_stream);

                let maybe_tls_acceptor_clone = maybe_tls_acceptor.clone();
                tokio::spawn(async move {
                    match maybe_tls_acceptor_clone {
                        Some(tls_acceptor) => {
                            match tls_acceptor.accept(counting_stream).await {
                                Ok(stream) => {
                                    let io = hyper_util::rt::TokioIo::new(stream);
                                    chorus::serve(io, hashed_peer).await;
                                },
                                Err(e) => {
                                    log::error!(
                                        target: "Client",
                                        "{}: TLS accept: {}", hashed_peer, e
                                    );
                                }
                            }
                        },
                        None => {
                            let io = hyper_util::rt::TokioIo::new(counting_stream);
                            chorus::serve(io, hashed_peer).await;
                        }
                    };
                });
            }
        };
    }

    // Pre-sync in case something below hangs up
    let _ = GLOBALS.store.get().unwrap().sync();

    // Set the shutting down signal
    let _ = GLOBALS.shutting_down.send(true);

    // Wait for active websockets to shutdown gracefully
    let mut num_connections = GLOBALS.num_connections.load(Ordering::Relaxed);
    if num_connections != 0 {
        log::info!(target: "Server", "Waiting for {num_connections} websockets to shutdown...");

        // We will check if all clients have shutdown every 25ms
        let interval = tokio::time::interval(Duration::from_millis(25));
        tokio::pin!(interval);

        while num_connections != 0 {
            // If we get another shutdown signal, stop waiting for websockets
            tokio::select! {
                v = interrupt_signal.recv() => if v.is_some() {
                    break;
                },
                v = quit_signal.recv() => if v.is_some() {
                    break;
                },
                v = terminate_signal.recv() => if v.is_some() {
                    break;
                },
                _instant = interval.tick() => {
                    num_connections = GLOBALS.num_connections.load(Ordering::Relaxed);
                    continue;
                }
            }
        }
    }

    log::info!(target: "Server", "Syncing and shutting down.");
    let _ = GLOBALS.store.get().unwrap().sync();

    chorus::print_stats();

    Ok(())
}
