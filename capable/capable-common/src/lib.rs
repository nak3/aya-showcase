#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
#[repr(packed)]
#[derive(Debug)]
pub struct Event {
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub cap: u32,
    pub audit: bool,
    pub insetid: bool,
    pub comm: [i8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
