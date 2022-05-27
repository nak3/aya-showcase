#![no_std]
#![no_main]

use aya_bpf::{
    macros::{cgroup_sysctl, map},
    maps::BloomFilter,
    programs::SysctlContext,
};

use aya_log_ebpf::info;

#[cgroup_sysctl(name = "cgroup_sysctl")]
pub fn cgroup_sysctl(ctx: SysctlContext) -> i32 {
    match unsafe { try_cgroup_sysctl(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map(name = "BLOOM_FILTER")]
static mut BLOOM_FILTER: BloomFilter<u32> = BloomFilter::<u32>::with_max_entries(30, 64);

unsafe fn try_cgroup_sysctl(ctx: SysctlContext) -> Result<i32, i32> {
    for key in 100..102 {
        match BloomFilter::<u32>::insert(&mut BLOOM_FILTER, key, 0) {
            Ok(()) => info!(&ctx, "key {} is inserted from BPF", key),
            Err(e) => info!(
                &ctx,
                "key {} fails to insert from BPF with error code {}", key, e
            ),
        }
    }

    for key in 100..103 {
        match BloomFilter::<u32>::contains(&mut BLOOM_FILTER, key) {
            Ok(()) => info!(&ctx, "key {} found from BPF", key),
            Err(e) => info!(&ctx, "key {} not found from BPF {}", key, e),
        }
    }

    info!(
        &ctx,
        "Let's check key 0 and 1 that were interted from userspace."
    );
    for key in 0..3 {
        match BloomFilter::<u32>::contains(&mut BLOOM_FILTER, key) {
            Ok(()) => info!(&ctx, "key {} found from BPF", key),
            Err(e) => info!(&ctx, "key {} not found from BPF with error code {}", key, e),
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
