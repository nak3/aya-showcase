#![no_std]
#![no_main]

use aya_bpf::{
    macros::{cgroup_sysctl, map},
    maps::Queue,
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

#[map(name = "QUEUE")]
static mut QUEUE: Queue<u32> = Queue::<u32>::with_max_entries(10, 0);

unsafe fn try_cgroup_sysctl(ctx: SysctlContext) -> Result<i32, i32> {
    match Queue::<u32>::pop(&mut QUEUE) {
        Some(val) => info!(&ctx, "value {} found", val), // This should be empty.
        None => info!(&ctx, "not found"),
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
