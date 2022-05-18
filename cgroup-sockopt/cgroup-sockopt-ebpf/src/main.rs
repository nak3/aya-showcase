#![no_std]
#![no_main]

use aya_bpf::{
    macros::{cgroup_sockopt, map},
    maps::PerfEventArray,
    programs::SockoptContext,
};

use aya_bpf::{cty::c_char, helpers::bpf_getsockopt};

use cgroup_sockopt_common::Event;

#[cgroup_sockopt(name = "cgroup_sockopt")]
pub fn cgroup_sockopt(ctx: SockoptContext) -> i32 {
    match unsafe { try_cgroup_sockopt(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::<Event>::with_max_entries(1024, 0);

unsafe fn try_cgroup_sockopt(ctx: SockoptContext) -> Result<i32, i32> {
    let mut buf: [c_char; 16] = [0; 16];

    let sockopt = ctx.sockopt;
    //let ret = bpf_getsockopt(ctx.sockopt, 0, &mut buf as *mut _ as *mut c_char, 16, 0);
    //let ret = bpf_getsockopt(ctx.sockopt, sockopt.level, sockopt.optname, sockopt.optval, sockopt.optlen);
    let ret = bpf_getsockopt(ctx.sockopt, (*sockopt).level, (*sockopt).optname, (*sockopt).optval(), (*sockopt).optlen);
    // TODO: handle ret

    let event = Event { name: buf };

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
