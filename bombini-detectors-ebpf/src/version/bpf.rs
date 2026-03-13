use super::KernelVersion;
use core::ptr;

#[unsafe(no_mangle)]
#[cfg(not(any(feature = "no-kernel-version")))]
static LINUX_KERNEL_VERSION: KernelVersion = KernelVersion::MIN_VERSION;

#[inline(always)]
pub fn kernel_version() -> KernelVersion {
    unsafe { ptr::read_volatile(&LINUX_KERNEL_VERSION) }
}
