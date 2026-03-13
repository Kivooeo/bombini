use super::shim::{self, *};
use super::{core_cred::cred, file, rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type linux_binprm = CoRe<shim::linux_binprm>;

impl linux_binprm {
    rust_shim_kernel_impl!(pub, linux_binprm, file, file);

    #[inline(always)]
    pub unsafe fn cred(&self) -> Option<cred> {
        if self.is_null() || !shim_linux_binprm_cred_exists(self.as_ptr_mut()) {
            return None;
        }
        let ptr = shim_linux_binprm_cred(self.as_ptr_mut());
        if ptr.is_null() { None } else { Some(CoRe::from_ptr(ptr)) }
    }
}
