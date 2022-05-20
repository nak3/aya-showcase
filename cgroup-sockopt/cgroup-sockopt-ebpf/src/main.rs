#![no_std]
#![no_main]

use aya_bpf::{
    macros::{cgroup_sockopt, map},
    maps::PerfEventArray,
    programs::SockoptContext,
};

use aya_log_ebpf::info;
use cgroup_sockopt_common::Event;

#[cgroup_sockopt(getsockopt,name="cgroup_sockopt")]
pub fn cgroup_sockopt(ctx: SockoptContext) -> i32 {
    match unsafe { try_cgroup_sockopt(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::<Event>::with_max_entries(1024, 0);

unsafe fn try_cgroup_sockopt(ctx: SockoptContext) -> Result<i32, i32> {
    let event = Event {
        name: (*ctx.sockopt).optname,
    };
    EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
