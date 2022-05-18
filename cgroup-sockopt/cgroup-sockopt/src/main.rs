use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::CgroupSockopt;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};

use bytes::BytesMut;
use cgroup_sockopt_common::Event;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::{signal, task};

use std::path::Path;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
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
        "../../target/bpfel-unknown-none/debug/cgroup-sockopt"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/cgroup-sockopt"
    ))?;
    let program: &mut CgroupSockopt = bpf.program_mut("cgroup_sockopt").unwrap().try_into()?;
    let cgroup_path = if Path::new(&opt.cgroup_path).exists() {
        opt.cgroup_path
    } else {
        "/sys/fs/cgroup".to_string()
    };
    let cgroup = std::fs::File::open(cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Event;
                    let event = unsafe { ptr.read_unaligned() };
                    let name = &event.name;

                    let str_buf =
                        String::from_utf8(name.iter().map(|&c| c as u8).collect()).unwrap();

                    println!("{:<20}", str_buf,);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
