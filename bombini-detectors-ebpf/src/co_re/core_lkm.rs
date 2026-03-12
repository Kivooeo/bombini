use super::shim::{self, *};
use super::{rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type load_info = CoRe<shim::load_info>;

impl load_info {
    rust_shim_kernel_impl!(pub, load_info, name, *const u8);
}
