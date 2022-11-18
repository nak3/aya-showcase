use aya::{include_bytes_aligned, Bpf};
use aya::{programs::LwtIn};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

use aya::maps::SockMap;
use aya::programs::SkSkb;

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/lwt-in"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/lwt-in"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

 let intercept_ingress: SockMap<_> = bpf.map("INTERCEPT_INGRESS").unwrap().try_into()?;
 let map_fd = intercept_ingress.fd()?;

let prog: &mut SkSkb = bpf.program_mut("encap_gre").unwrap().try_into()?;
prog.load()?;
prog.attach(map_fd)?;


    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
