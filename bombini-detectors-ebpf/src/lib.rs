#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", allow(static_mut_refs))]

use macros::bpf_target_code;

pub mod macros;

pub mod string;
pub mod utils;
pub mod util;
pub mod filter;
pub mod interpreter;
pub mod event_map;
pub mod dyn_ringbuf;

pub mod alloc;
pub mod errors;
pub mod syscalls;

bpf_target_code! {
    pub mod co_re;
}

pub mod bpf_events;
pub mod net;
pub mod path;

pub mod consts;

pub mod buffer;

pub mod uuid;

pub mod cgroup;
pub mod time;

pub mod config;

pub mod version;

pub mod io_uring;
pub mod vmlinux;
