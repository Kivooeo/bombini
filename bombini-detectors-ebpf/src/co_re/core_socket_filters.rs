use super::shim::{self, *};
use super::{CoRe, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type sock_fprog = CoRe<shim::sock_fprog>;

impl sock_fprog {
    rust_shim_kernel_impl!(pub, sock_fprog, len, u16);
    rust_shim_kernel_impl!(pub, sock_fprog, filter, sock_filter);

    #[inline(always)]
    pub unsafe fn size(&self) -> Option<usize> {
        Some(unsafe { self.len() }? as usize * core::mem::size_of::<shim::sock_filter>())
    }
}

#[allow(non_camel_case_types)]
pub type sock_fprog_kern = CoRe<shim::sock_fprog_kern>;

impl sock_fprog_kern {
    rust_shim_kernel_impl!(pub, sock_fprog_kern, len, u16);
    rust_shim_kernel_impl!(pub, sock_fprog_kern, filter, sock_filter);

    #[inline(always)]
    pub unsafe fn byte_size_from_len(len: u16) -> usize {
        len as usize * core::mem::size_of::<shim::sock_filter>()
    }

    #[inline(always)]
    pub unsafe fn byte_size(&self) -> Option<usize> {
        Some(Self::byte_size_from_len(self.len()?))
    }
}

#[allow(non_camel_case_types)]
pub type sock_filter = CoRe<shim::sock_filter>;

impl sock_filter {
    rust_shim_kernel_impl!(pub, sock_filter, code, u16);
    rust_shim_kernel_impl!(pub, sock_filter, jt, u8);
    rust_shim_kernel_impl!(pub, sock_filter, jf, u8);
    rust_shim_kernel_impl!(pub, sock_filter, k, u32);
}
