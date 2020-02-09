#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(const_raw_ptr_to_usize_cast)]
#![feature(extern_types)]
#![feature(ptr_wrapping_offset_from)]
#![feature(register_tool)]
#![register_tool(c2rust)]

extern crate libc;

pub mod src {
    pub mod contrib {
        pub mod lax_der_parsing;
    } // mod contrib
    pub mod src {
        pub mod secp256k1;
    } // mod src
} // mod src
