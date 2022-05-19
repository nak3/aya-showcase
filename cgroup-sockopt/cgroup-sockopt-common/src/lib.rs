#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
#[repr(packed)]
#[derive(Debug)]
pub struct Event {
    //pub name: [i8; 16],
    pub name: i32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
