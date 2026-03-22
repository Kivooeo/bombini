//! Kernel `struct cred` readers for procmon LSM and tracepoint programs.
//!
//! All accesses go through [`bpf_probe_read_kernel`] and `vmlinux` types. Userspace loads with
//! [`aya::EbpfLoader::btf`] and `/sys/kernel/btf/vmlinux` so CO-RE relocations in the object are
//! applied when the toolchain emits them.

use aya_ebpf::helpers::bpf_probe_read_kernel;
use bombini_common::event::process::{Capabilities, ProcInfo};

use crate::vmlinux::{cred, kernel_cap_t, kgid_t, kuid_t};

#[inline(always)]
unsafe fn read_kuid(p: *const kuid_t) -> Result<u32, u32> {
    unsafe {
        bpf_probe_read_kernel::<kuid_t>(p)
            .map(|k| k.val)
            .map_err(|_| 0u32)
    }
}

#[inline(always)]
unsafe fn read_kgid(p: *const kgid_t) -> Result<u32, u32> {
    unsafe {
        bpf_probe_read_kernel::<kgid_t>(p)
            .map(|k| k.val)
            .map_err(|_| 0u32)
    }
}

#[inline(always)]
unsafe fn read_cap(p: *const kernel_cap_t) -> Result<u64, u32> {
    unsafe {
        bpf_probe_read_kernel::<kernel_cap_t>(p)
            .map(|k| k.val)
            .map_err(|_| 0u32)
    }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_uid(c: *const cred) -> Result<u32, u32> {
    unsafe { read_kuid(core::ptr::addr_of!((*c).uid)) }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_euid(c: *const cred) -> Result<u32, u32> {
    unsafe { read_kuid(core::ptr::addr_of!((*c).euid)) }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_fsuid(c: *const cred) -> Result<u32, u32> {
    unsafe { read_kuid(core::ptr::addr_of!((*c).fsuid)) }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_gid(c: *const cred) -> Result<u32, u32> {
    unsafe { read_kgid(core::ptr::addr_of!((*c).gid)) }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_egid(c: *const cred) -> Result<u32, u32> {
    unsafe { read_kgid(core::ptr::addr_of!((*c).egid)) }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_fsgid(c: *const cred) -> Result<u32, u32> {
    unsafe { read_kgid(core::ptr::addr_of!((*c).fsgid)) }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_cap_effective(c: *const cred) -> Result<u64, u32> {
    unsafe { read_cap(core::ptr::addr_of!((*c).cap_effective)) }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_cap_inheritable(c: *const cred) -> Result<u64, u32> {
    unsafe { read_cap(core::ptr::addr_of!((*c).cap_inheritable)) }
}

/// # Safety
/// `c` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn cred_cap_permitted(c: *const cred) -> Result<u64, u32> {
    unsafe { read_cap(core::ptr::addr_of!((*c).cap_permitted)) }
}

/// # Safety
/// `cred` must point to a valid kernel `struct cred`.
#[inline(always)]
pub unsafe fn fill_proc_creds(proc: &mut ProcInfo, cred: *const cred) -> Result<(), u32> {
    unsafe {
        proc.creds.cap_effective =
            Capabilities::from_bits_retain(cred_cap_effective(cred)?);
        proc.creds.cap_inheritable =
            Capabilities::from_bits_retain(cred_cap_inheritable(cred)?);
        proc.creds.cap_permitted =
            Capabilities::from_bits_retain(cred_cap_permitted(cred)?);
        proc.creds.uid = cred_uid(cred)?;
        proc.creds.euid = cred_euid(cred)?;
        proc.creds.gid = cred_gid(cred)?;
        proc.creds.egid = cred_egid(cred)?;
    }
    Ok(())
}
