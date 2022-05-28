#![no_std]
#![no_main]

use aya_bpf::{
    macros::{cgroup_sysctl, map},
    maps::Stack,
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

#[map(name = "STACK")]
static mut STACK: Stack<u32> = Stack::<u32>::with_max_entries(10, 0);

unsafe fn try_cgroup_sysctl(ctx: SysctlContext) -> Result<i32, i32> {
    match Stack::<u32>::push(&mut STACK, &1, 0) {
        Ok(()) => info!(&ctx, "value pushed"), // This should be empty.
        Err(e) => info!(&ctx, "failed to push {}", e),
    }
    match Stack::<u32>::push(&mut STACK, &2, 0) {
        Ok(()) => info!(&ctx, "value pushed"), // This should be empty.
        Err(e) => info!(&ctx, "failed to push {}", e),
    }
    match Stack::<u32>::pop(&mut STACK) {
        Some(val) => info!(&ctx, "value {} found", val), // This should be empty.
        None => info!(&ctx, "not found"),
    }
    match Stack::<u32>::pop(&mut STACK) {
        Some(val) => info!(&ctx, "value {} found", val), // This should be empty.
        None => info!(&ctx, "not found"),
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
