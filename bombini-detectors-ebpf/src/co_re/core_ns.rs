use super::shim::{self, *};
use super::{mount, rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type nsproxy = CoRe<shim::nsproxy>;

impl nsproxy {
    rust_shim_kernel_impl!(pub, nsproxy, mnt_ns, mnt_namespace);
    rust_shim_kernel_impl!(pub, nsproxy, uts_ns, uts_namespace);
}

#[allow(non_camel_case_types)]
pub type ns_common = CoRe<shim::ns_common>;

impl ns_common {
    rust_shim_kernel_impl!(ns_common, inum, u32);
}

#[allow(non_camel_case_types)]
pub type mnt_namespace = CoRe<shim::mnt_namespace>;

impl mnt_namespace {
    rust_shim_kernel_impl!(mnt_namespace, ns, ns_common);
    rust_shim_kernel_impl!(mnt_namespace, root, mount);
    rust_shim_kernel_impl!(mnt_namespace, mounts, u32);
}

#[allow(non_camel_case_types)]
pub type uts_namespace = CoRe<shim::uts_namespace>;

impl uts_namespace {
    rust_shim_kernel_impl!(uts_namespace, ns, ns_common);
    rust_shim_kernel_impl!(uts_namespace, name, new_utsname);
}

#[allow(non_camel_case_types)]
pub type new_utsname = CoRe<shim::new_utsname>;

impl new_utsname {
    rust_shim_kernel_impl!(new_utsname, sysname, *mut i8);
    rust_shim_kernel_impl!(new_utsname, nodename, *mut i8);
    rust_shim_kernel_impl!(new_utsname, release, *mut i8);
    rust_shim_kernel_impl!(new_utsname, version, *mut i8);
    rust_shim_kernel_impl!(new_utsname, machine, *mut i8);
    rust_shim_kernel_impl!(new_utsname, domainname, *mut i8);
}
