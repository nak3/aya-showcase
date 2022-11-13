#![no_std]
#![no_main]

use aya_bpf_cty::c_void;

use aya_bpf::{
    programs::LwtInContext,
    helpers::bpf_lwt_push_encap,
    cty::c_char,
//    bindings::iphdr,
};
use core::mem;



use aya_bpf_macros::lwt_in;


use aya_log_ebpf::info;

/*
 * from libbpf
enum lwtunnel_encap_types {
        LWTUNNEL_ENCAP_NONE = 0,
        LWTUNNEL_ENCAP_MPLS = 1,
        LWTUNNEL_ENCAP_IP = 2,
        LWTUNNEL_ENCAP_ILA = 3,
        LWTUNNEL_ENCAP_IP6 = 4,
        LWTUNNEL_ENCAP_SEG6 = 5, 
        LWTUNNEL_ENCAP_BPF = 6,
        LWTUNNEL_ENCAP_SEG6_LOCAL = 7,
        LWTUNNEL_ENCAP_RPL = 8,
        LWTUNNEL_ENCAP_IOAM6 = 9,
        __LWTUNNEL_ENCAP_MAX = 10,
}; 

struct lwtunnel_encap_ops {
        int (*build_state)(struct net *, struct nlattr *, unsigned int, const void *, struct lwtunnel_state **, struct netlink_ext_ack *);
        void (*destroy_state)(struct lwtunnel_state *);
        int (*output)(struct net *, struct sock *, struct sk_buff *);
        int (*input)(struct sk_buff *);
        int (*fill_encap)(struct sk_buff *, struct lwtunnel_state *);
        int (*get_encap_size)(struct lwtunnel_state *);
        int (*cmp_encap)(struct lwtunnel_state *, struct lwtunnel_state *);
        int (*xmit)(struct sk_buff *);
        struct module *owner;
};

*/


#[lwt_in(name="encap_gre")]
pub fn encap_gre(ctx: LwtInContext) -> i32 {
    match try_encap_gre(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub struct grehdr {

}

pub struct iphdr {

}

pub struct encap_hdr {
    ip_hdr: iphdr,
    gre_hdr: grehdr,
}   

fn try_encap_gre(ctx: LwtInContext) -> Result<i32, i32> {
    info!(&ctx, "LWT_IN encap_gre called");

    let mut hdr = encap_hdr{ 
        //ip_hdr: iphdr{_unused: []},
        ip_hdr: iphdr{},
        gre_hdr: grehdr{},
    };

    // see linux's ./tools/testing/selftests/bpf/progs/test_lwt_ip_encap.c
    //
    //let ret = bpf_lwt_push_encap(&mut ctx.skb as *mut _ as *mut c_char, 16, 0);
    let ret = unsafe {
        bpf_lwt_push_encap(ctx.skb.skb,  2 /* LWTUNNEL_ENCAP_IP */, &mut hdr as *mut _ as *mut aya_bpf_cty::c_void, mem::size_of::<encap_hdr>() as u32);
    };

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
