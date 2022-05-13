#![no_std]
#![no_main]

use aya_bpf::{
    macros::{cgroup_sysctl, map},
    maps::PerfEventArray,
    programs::SysctlContext,
};

use aya_bpf::{cty::c_char, helpers::bpf_sysctl_get_name};

use cgroup_sysctl_common::Event;

#[cgroup_sysctl(name = "cgroup_sysctl")]
pub fn cgroup_sysctl(ctx: SysctlContext) -> i32 {
    match unsafe { try_cgroup_sysctl(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::<Event>::with_max_entries(1024, 0);

unsafe fn try_cgroup_sysctl(ctx: SysctlContext) -> Result<i32, i32> {
    let mut buf: [c_char; 16] = [0; 16];

    let ret = bpf_sysctl_get_name(ctx.sysctl, &mut buf as *mut _ as *mut c_char, 16, 0);
    // TODO: handle ret

    let event = Event { name: buf };

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
