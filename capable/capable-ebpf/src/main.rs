#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_get_current_comm,
    helpers::bpf_get_current_pid_tgid,
    helpers::bpf_get_current_uid_gid,
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
};

use capable_common::Event;

#[kprobe(name = "capable")]
pub fn capable(ctx: ProbeContext) -> u32 {
    match unsafe { try_capable(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::<Event>::with_max_entries(1024, 0);

unsafe fn try_capable(ctx: ProbeContext) -> Result<u32, u32> {
    let cap: u32 = ctx.arg(2).ok_or(1u32)?;
    let cap_opt: u32 = ctx.arg(3).ok_or(1u32)?;

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = match bpf_get_current_comm() {
        Err(_) => panic!(),
        Ok(c) => c,
    };

    // TODO: Linux kernel >= 5.1.0
    let (audit, insetid) = ((cap_opt & 0b10) == 0, (cap_opt & 0b1000) != 0);

    let capable = Event {
        tgid: tgid,
        pid: pid,
        uid: uid,
        cap: cap,
        audit: audit,
        insetid: insetid,
        comm: comm,
    };

    EVENTS.output(&ctx, &capable, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
