use std::os::raw::{c_int, c_long};

#[link(name = "foo", kind = "static")]
extern "C" {
    fn func_ret_int() -> c_long;
    fn func_ret_long() -> c_int;
}

fn main() {
    let pointer = func_ret_int as *const ();

    let fun: unsafe fn() -> c_long = unsafe { std::mem::transmute(pointer) };
    let ans: c_long = unsafe { fun() };
    println!("-2 (Rust: c_long, C: int) => {}", ans);

    let fun: unsafe fn() -> c_int = unsafe { std::mem::transmute(pointer) };
    let ans: c_int = unsafe { fun() };
    println!("-2 (Rust: c_int, C: int) => {}", ans);

    unsafe {
        println!(
            "-2 (Rust: c_long, C: int, no transmute) => {}",
            func_ret_int()
        );
    }

    let pointer = func_ret_long as *const ();

    let fun: unsafe fn() -> c_long = unsafe { std::mem::transmute(pointer) };
    let ans: c_long = unsafe { fun() };
    println!("-2 (Rust: c_long, C: long) => {}", ans);

    let fun: unsafe fn() -> c_int = unsafe { std::mem::transmute(pointer) };
    let ans: c_int = unsafe { fun() };
    println!("-2 (Rust: c_int, C: long) => {}", ans);

    unsafe {
        println!(
            "-2 (Rust: c_int, C: long, no transmute) => {}",
            func_ret_long()
        );
    }

}
