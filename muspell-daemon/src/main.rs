use clap::{Parser, Subcommand};
use iroh::{endpoint::presets, Endpoint, EndpointId};
use tracing::{info, warn};
use std::time::Duration;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run,
    Connect {
        endpoint_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let endpoint = Endpoint::builder(presets::N0)
        .bind()
        .await
        .map_err(|e| format!("Failed to bind: {}", e))?;

    let my_id = endpoint.id();

    info!(" Muspell Daemon started");
    info!("   My EndpointID : {}", my_id);

    match args.command {
        Commands::Run => {
            info!(" Listening mode");
            info!("Share this ID to connect:");
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

                    match connecting.await {
                        Ok(conn) => {
                            info!(" Connected from {}", conn.remote_id());
                            // For minimal test, just close
                            conn.close(0u32.into(), b"ok");
                        }
                        Err(e) => warn!("Connection failed: {}", e),
                    }
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

            info!("Connecting to {}", peer_id);

            let peer_addr = iroh::EndpointAddr::from(peer_id);

            // Use Iroh's most common default ALPN
            const ALPN: &[u8] = b"/iroh/0.1";

            match tokio::time::timeout(Duration::from_secs(45), endpoint.connect(peer_addr, ALPN)).await {
                Ok(Ok(conn)) => {
                    info!(" Connected successfully to {}", peer_id);
                    info!("You can now send data over this connection.");
                    // Keep connection alive for a bit
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
                Ok(Err(e)) => warn!("Failed to connect: {}", e),
                Err(_) => warn!("Timed out"),
            }
        }
    }

    Ok(())
}
