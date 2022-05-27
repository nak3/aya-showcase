use aya::maps::bloom_filter::BloomFilter;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;

use aya::programs::CgroupSysctl;

use aya::maps::MapRefMut;

use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/user.slice")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/bloom-filter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/bloom-filter"
    ))?;

    BpfLogger::init(&mut bpf)?;

    let bloom_filter = BloomFilter::<MapRefMut, u32>::try_from(bpf.map_mut("BLOOM_FILTER")?)?;
    for key in 0..2 {
        bloom_filter.insert(key, 0)?;
        println!("key {} is inserted", key);
    }
    for key in 0..3 {
        match bloom_filter.contains(key, 0) {
            Ok(()) => println!("key {} found", key),
            Err(e) => println!("key {} not found with error: {}", key, e),
        }
    }

    let program: &mut CgroupSysctl = bpf.program_mut("cgroup_sysctl").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
