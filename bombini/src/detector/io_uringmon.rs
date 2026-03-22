//! IOUring detector

use aya::programs::BtfTracePoint;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use procfs::sys::kernel::Version;

use std::path::Path;

use super::ebpf::require_kernel_btf;
use super::Detector;

pub struct IOUringMon {
    ebpf: Ebpf,
}

impl IOUringMon {
    pub fn new<P>(obj_path: P, maps_pin_path: P) -> Result<Self, anyhow::Error>
    where
        P: AsRef<Path>,
    {
        let btf = require_kernel_btf().map_err(|e| {
            anyhow::anyhow!(
                "CO-RE requires kernel BTF at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF): {e}"
            )
        })?;
        let mut ebpf_loader = EbpfLoader::new();
        let ebpf_loader_ref = ebpf_loader
            .map_pin_path(maps_pin_path.as_ref())
            .btf(Some(&btf));
        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;
        Ok(IOUringMon { ebpf })
    }
}

impl Detector for IOUringMon {
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        let submit: &mut BtfTracePoint = self
            .ebpf
            .program_mut("io_uring_submit_req_capture")
            .unwrap()
            .try_into()?;
        submit.load("io_uring_submit_req", &btf)?;
        submit.attach()?;
        Ok(())
    }

    fn min_kenrel_verison(&self) -> Version {
        Version::new(6, 8, 0)
    }
}
