//! Original destination recovery for NAT-redirected connections.
//!
//! Platform-specific implementations:
//! - **macOS**: Uses `DIOCNATLOOK` ioctl on `/dev/pf` to query pf's NAT state table
//! - **Linux**: Uses `SO_ORIGINAL_DST` getsockopt on the accepted socket fd

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{get_original_dest, NatHandle};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{get_original_dest, NatHandle};
