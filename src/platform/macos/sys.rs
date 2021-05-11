#![allow(non_camel_case_types)]
#[repr(C)]
pub struct ctl_info {
    pub ctl_id: u32,
    pub ctl_name: [u8; 96],
}
ioctl_sys::ioctl!(readwrite ctliocginfo with 'N', 3; ctl_info);

#[repr(C)]
pub struct rt_msghdr {
    pub rtm_msglen: u16,
    pub rtm_version: u8,
    pub rtm_type: u8,
    pub rtm_index: u16,
    pub rtm_flags: i32,
    pub rtm_addrs: i32,
    pub rtm_pid: libc::pid_t,
    pub rtm_seq: i32,
    pub rtm_errno: i32,
    pub rtm_use: i32,
    pub rtm_inits: u32,
    pub rtm_rmx: rt_metrics,
}

#[repr(C)]
pub struct rt_metrics {
    pub rmx_locks: u32,       /* Kernel must leave these values alone */
    pub rmx_mtu: u32,         /* MTU for this path */
    pub rmx_hopcount: u32,    /* max hops expected */
    pub rmx_expire: i32,      /* lifetime for route, e.g. redirect */
    pub rmx_recvpipe: u32,    /* inbound delay-bandwidth product */
    pub rmx_sendpipe: u32,    /* outbound delay-bandwidth product */
    pub rmx_ssthresh: u32,    /* outbound gateway buffer limit */
    pub rmx_rtt: u32,         /* estimated round trip time */
    pub rmx_rttvar: u32,      /* estimated rtt variance */
    pub rmx_pksent: u32,      /* packets sent using this route */
    pub rmx_filler: [u32; 4], /* will be used for T/TCP later */
}
