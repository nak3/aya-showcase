#![no_std]
#![no_main]

use aya_bpf::{
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::info;

#[lsm(name="file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    info!(&ctx, "lsm hook file_open called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
