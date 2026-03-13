#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
pub mod  shim;
pub use shim::timespec64;

pub mod  core_task_struct;
pub use core_task_struct::*;

pub mod  core_cred;
pub use core_cred::*;

pub mod  core_mm_struct;
pub use core_mm_struct::*;

pub mod  core_fs;
pub use core_fs::*;

pub mod  core_exec;
pub use core_exec::*;

pub mod  core_bpf;
pub use core_bpf::*;

pub mod  core_socket_filters;
pub use core_socket_filters::*;

pub mod  core_lkm;
pub use core_lkm::*;

pub mod  core_sock;
pub use core_sock::*;

pub mod  core_iov;
pub use core_iov::*;

pub mod  core_ns;
pub use core_ns::*;

pub mod  core_cgroup;
pub use core_cgroup::*;

pub mod  core_kernfs;
pub use core_kernfs::*;

pub mod  core_clone_args;
pub use core_clone_args::*;

pub mod  core_files_struct;
pub use core_files_struct::*;

pub mod  core_page;
pub use core_page::*;

pub mod  core_io_uring;
pub use core_io_uring::*;

#[derive(Clone, Copy)]
pub struct CoRe<P> {
    ptr: *const P,
}

impl<P> PartialEq for CoRe<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl<P> From<*mut P> for CoRe<P> {
    fn from(value: *mut P) -> Self {
        Self::from_ptr(value)
    }
}

impl<P> From<*const P> for CoRe<P> {
    fn from(value: *const P) -> Self {
        Self::from_ptr(value)
    }
}

impl<P> CoRe<P> {
    #[inline(always)]
    pub unsafe fn bpf_read(&self) -> Result<*const P, i64> {
        unsafe { aya_ebpf::helpers::bpf_probe_read(&self.ptr) }
    }

    #[inline(always)]
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    pub fn as_ptr(&self) -> *const P {
        self.ptr as *mut _
    }

    fn as_ptr_mut(&self) -> *mut P {
        self.ptr as *mut _
    }

    pub fn from_ptr(ptr: *const P) -> Self {
        CoRe {
            ptr: ptr as *const _,
        }
    }
}

macro_rules! rust_shim_kernel_impl {
    ($struct:ident, $member:ident, $ret:ty) => {
        rust_shim_kernel_impl! (pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $struct:ident, $member:ident, $ret:ty) => {
        rust_shim_kernel_impl! ($pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $fn_name:ident, $struct: ident, $member:ident, $ret:ty) => {
        #[inline(always)]
        $pub unsafe fn $fn_name(&self) -> Option<$ret> {
            if !self.is_null()
                && paste::paste! {[<shim_ $struct _ $member _exists>]}(self.as_ptr_mut())
            {
                return Some(paste::paste! {[<shim_ $struct _ $member>]}(self.as_ptr_mut()).into());
            }
            None
        }
    };
}

pub(crate) use rust_shim_kernel_impl;

macro_rules! rust_shim_user_impl {
    ($pub:vis, $struct:ident, $member:ident, $ret:ty) => {
        rust_shim_user_impl! ($pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $fn_name:ident, $struct: ident, $member:ident, $ret:ty) => {
        paste::item!{
        #[inline(always)]
        $pub unsafe fn [<$fn_name _user>] (&self) -> Option<$ret> {
            if !self.is_null()
                && [<shim_ $struct _ $member _exists>](self.as_ptr_mut())
            {
                return Some(paste::paste! {[<shim_ $struct _ $member _user>]}(self.as_ptr_mut()).into());
            }
            None
        }
        }
    };
}

pub(crate) use rust_shim_user_impl;

#[macro_export]
macro_rules! core_read_kernel {
    ($struc:expr, $field:ident) => {
        $struc
            .$field()
    };

    ($struc:expr, $first:ident, $($rest: ident),*) => {
        $struc
            .$first()
            $(
            .and_then(|r| r.$rest())
            )*
    };
}

pub use core_read_kernel;
