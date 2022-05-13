use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};

use bytes::BytesMut;
use capable_common::Event;
use chrono::Local;
use log::info;
use phf::phf_map;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::{signal, task};

static CAPS: phf::Map<u32, &'static str> = phf_map! {
    0u32 => "CAP_CHOWN",
    1u32 => "CAP_DAC_OVERRIDE",
    2u32 => "CAP_DAC_READ_SEARCH",
    3u32 => "CAP_FOWNER",
    4u32 => "CAP_FSETID",
    5u32 => "CAP_KILL",
    6u32 => "CAP_SETGID",
    7u32 => "CAP_SETUID",
    8u32 => "CAP_SETPCAP",
    9u32 => "CAP_LINUX_IMMUTABLE",
    10u32 => "CAP_NET_BIND_SERVICE",
    11u32 => "CAP_NET_BROADCAST",
    12u32 => "CAP_NET_ADMIN",
    13u32 => "CAP_NET_RAW",
    14u32 => "CAP_IPC_LOCK",
    15u32 => "CAP_IPC_OWNER",
    16u32 => "CAP_SYS_MODULE",
    17u32 => "CAP_SYS_RAWIO",
    18u32 => "CAP_SYS_CHROOT",
    19u32 => "CAP_SYS_PTRACE",
    20u32 => "CAP_SYS_PACCT",
    21u32 => "CAP_SYS_ADMIN",
    22u32 => "CAP_SYS_BOOT",
    23u32 => "CAP_SYS_NICE",
    24u32 => "CAP_SYS_RESOURCE",
    25u32 => "CAP_SYS_TIME",
    26u32 => "CAP_SYS_TTY_CONFIG",
    27u32 => "CAP_MKNOD",
    28u32 => "CAP_LEASE",
    29u32 => "CAP_AUDIT_WRITE",
    30u32 => "CAP_AUDIT_CONTROL",
    31u32 => "CAP_SETFCAP",
    32u32 => "CAP_MAC_OVERRIDE",
    33u32 => "CAP_MAC_ADMIN",
    34u32 => "CAP_SYSLOG",
    35u32 => "CAP_WAKE_ALARM",
    36u32 => "CAP_BLOCK_SUSPEND",
    37u32 => "CAP_AUDIT_READ",
    38u32 => "CAP_PERFMON",
    39u32 => "CAP_BPF",
    40u32 => "CAP_CHECKPOINT_RESTORE",
};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
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
        "../../target/bpfel-unknown-none/debug/capable"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/capable"
    ))?;
    let program: &mut KProbe = bpf.program_mut("capable").unwrap().try_into()?;
    program.load()?;
    program.attach("cap_capable", 0)?;

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

                    let cap_name = match CAPS.get(&event.cap) {
                        Some(&x) => x,
                        None => "?",
                    };

                    let comm = &event.comm;
                    let comm_str =
                        String::from_utf8(comm.iter().map(|&c| c as u8).collect()).unwrap();

                    println!(
                        "{:9} {:6} {:<6} {:<16} {:<4} {:<20} {:<6}",
                        Local::now().format("%H:%M:%S"),
                        event.uid,
                        event.tgid,
                        comm_str,
                        event.cap,
                        cap_name,
                        event.audit
                    );
                }
            }
        });
    }

    signal::ctrl_c().await.expect("failed to listen for event");
    info!("Exiting...");
    Ok::<_, anyhow::Error>(())
}
