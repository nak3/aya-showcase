use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::CgroupSockopt;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;

use bytes::BytesMut;
use cgroup_sockopt_common::Event;
use clap::Parser;
use log::info;
use phf::phf_map;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/user.slice")]
    cgroup_path: String,
}

static OPTNAMES: phf::Map<i32, &'static str> = phf_map! {
    1i32  => "IP_TOS",
    2i32 =>  "IP_TTL",
    3i32 =>  "IP_HDRINCL",
    4i32 =>  "IP_OPTIONS",
    5i32 =>  "IP_ROUTER_ALERT",
    6i32 =>  "IP_RECVOPTS",
    7i32 =>  "IP_RETOPTS",
    8i32 =>  "IP_PKTINFO",
    9i32 =>  "IP_PKTOPTIONS",
    10i32 => "IP_MTU_DISCOVER",
    11i32 => "IP_RECVERR",
    12i32 => "IP_RECVTTL",
    13i32 => "IP_RECVTOS",
    14i32 => "IP_MTU",
    15i32 => "IP_FREEBIND",
    16i32 => "IP_IPSEC_POLICY",
    17i32 => "IP_XFRM_POLICY",
    18i32 => "IP_PASSSEC",
    19i32 => "IP_TRANSPARENT",
    20i32 => "IP_ORIGDSTADDR",
    21i32 => "IP_MINTTL",
    22i32 => "IP_NODEFRAG",
    23i32 => "IP_CHECKSUM",
    24i32 => "IP_BIND_ADDRESS_NO_PORT",
    25i32 => "IP_RECVFRAGSIZE",
    26i32 => "IP_RECVERR_RFC4884",
};

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
    BpfLogger::init(&mut bpf)?;
    let program: &mut CgroupSockopt = bpf.program_mut("cgroup_sockopt").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
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
                    let opt_name = match OPTNAMES.get(&event.name) {
                        Some(&x) => x,
                        None => "?",
                    };

                    println!("optname: {}", opt_name);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
