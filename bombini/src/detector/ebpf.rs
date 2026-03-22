//! Shared eBPF loader helpers.
//!
//! Loaders pass [`Btf::from_sys_fs`] so the kernel can apply CO-RE relocations present in the ELF.
//! (Linking eBPF with `bpf-linker --btf` is not enabled here: BTF map definitions currently mis-size
//! some values such as `Capabilities`, which breaks userspace map handles.)

use aya::{Btf, BtfError};

/// Load `/sys/kernel/btf/vmlinux`. Required for CO-RE relocations at load time (`CONFIG_DEBUG_INFO_BTF`).
pub fn require_kernel_btf() -> Result<Btf, BtfError> {
    Btf::from_sys_fs()
}
