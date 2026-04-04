use clap::{Parser, Subcommand};
use iroh::{endpoint::presets, Endpoint, EndpointId};
use tracing::{info, warn};

//  Single source of truth — both sides MUST use identical bytes
const ALPN: &[u8] = b"/muspell/0.1";

#[derive(Parser)]
#[command(author, version, about = "Simple Muspell - Iroh connectivity tool")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start listening for connections
    Run,
    /// Connect to another machine by EndpointID
    Connect {
        /// EndpointID of the peer (z32 string)
        endpoint_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    //  Register ALPN on the builder so the listener advertises it in TLS
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| format!("Failed to bind Iroh: {}", e))?;

    let my_id = endpoint.id();
    info!(" Muspell started");
    info!("Your EndpointID: {}", my_id);

    match args.command {
        Commands::Run => {
            info!(" Listening for connections...");
            info!("Share this ID:");
            info!("{}", my_id);

            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let connecting = match incoming.accept() {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("Accept failed: {}", e);
                            return;
                        }
                    };
                    let conn = match connecting.await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("Connection failed: {}", e);
                            return;
                        }
                    };
                    info!(" Connected from {}", conn.remote_id());
                    conn.close(0u32.into(), b"ok");
                });
            }
        }

        Commands::Connect { endpoint_id } => {
            let peer_id: EndpointId = match endpoint_id.parse() {
                Ok(id) => id,
                Err(_) => {
                    warn!("Invalid EndpointID");
                    return Ok(());
                }
            };

            info!(" Connecting to {}", peer_id);
            let peer_addr = iroh::EndpointAddr::from(peer_id);

            match endpoint.connect(peer_addr, ALPN).await {
                Ok(conn) => {
                    info!(" Successfully connected to {}", peer_id);
                    info!("Connection is open. (We can add sending data later)");
                    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                    conn.close(0u32.into(), b"ok");
                }
                Err(e) => warn!("Failed to connect: {}", e),
            }
        }
    }

    Ok(())
}
