#![allow(unused_assignments)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::needless_return)]
#![allow(clippy::let_and_return)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::precedence)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::toplevel_ref_arg)]
#![forbid(clippy::unnecessary_mut_passed)]
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
