#![no_std]
#![no_main]

use aya_bpf::{
    programs::LwtInContext,
};

use aya_bpf_macros::lwt_in;

use aya_log_ebpf::info;

#[lwt_in(name="file_open")]
pub fn file_open(ctx: LwtInContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LwtInContext) -> Result<i32, i32> {
    info!(&ctx, "lsm hook file_open called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
