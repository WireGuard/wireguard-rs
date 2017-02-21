//! Bindgen source code
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]

pub const TUNSETIFF: u64 = (1 << 0 + 8 + 8 + 14) | (84 << 0 + 8) | (202 << 0) | (4 << 0 + 8 + 8);

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl ifreq {
    /// Create a new `ifreq`
    pub fn new() -> Self {
        ifreq {
            ifr_ifrn: ifreq__bindgen_ty_1 {
                ifrn_name: __BindgenUnionField::new(),
                bindgen_union_field: [0; IFNAMSIZ as usize],
            },
            ifr_ifru: ifreq__bindgen_ty_2 {
                ifru_addr: __BindgenUnionField::new(),
                ifru_dstaddr: __BindgenUnionField::new(),
                ifru_broadaddr: __BindgenUnionField::new(),
                ifru_netmask: __BindgenUnionField::new(),
                ifru_hwaddr: __BindgenUnionField::new(),
                ifru_flags: __BindgenUnionField::new(),
                ifru_ivalue: __BindgenUnionField::new(),
                ifru_mtu: __BindgenUnionField::new(),
                ifru_map: __BindgenUnionField::new(),
                ifru_slave: __BindgenUnionField::new(),
                ifru_newname: __BindgenUnionField::new(),
                ifru_data: __BindgenUnionField::new(),
                bindgen_union_field: [0u64; 3usize],
            },
        }
    }
}
