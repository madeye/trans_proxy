//! LAN gateway advertisement via gratuitous ARP and ICMPv6 Router Advertisement.
//!
//! When enabled with `--gateway`, periodically broadcasts:
//! - **Gratuitous ARP** (IPv4): spoofs the default gateway's IP with this
//!   machine's MAC so LAN devices route IPv4 traffic through us.
//! - **Router Advertisement** (IPv6): announces this machine as the preferred
//!   IPv6 default router with high priority.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

const ARP_INTERVAL: Duration = Duration::from_secs(2);
const RA_INTERVAL_TICKS: u64 = 15; // send RA every 15 ARP ticks = 30s
const RA_ROUTER_LIFETIME: u16 = 1800;

// ── Interface helpers ──────────────────────────────────────────────────

fn get_mac_address(iface: &str) -> Result<[u8; 6]> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/sys/class/net/{}/address", iface);
        let content =
            std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path))?;
        parse_mac(content.trim())
    }
    #[cfg(target_os = "macos")]
    {
        get_mac_address_macos(iface)
    }
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("invalid MAC address: {}", s);
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).with_context(|| format!("invalid MAC octet: {}", p))?;
    }
    Ok(mac)
}

#[cfg(target_os = "macos")]
fn get_mac_address_macos(iface: &str) -> Result<[u8; 6]> {
    use std::ffi::CString;
    let ifname = CString::new(iface)?;
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            bail!("getifaddrs failed");
        }
        let mut cursor = ifaddrs;
        let mut result = None;
        while !cursor.is_null() {
            let ifa = &*cursor;
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name);
            if name == ifname.as_c_str()
                && !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family as libc::c_int == libc::AF_LINK
            {
                let sdl = ifa.ifa_addr as *const libc::sockaddr_dl;
                let nlen = (*sdl).sdl_nlen as usize;
                let data = (*sdl).sdl_data.as_ptr() as *const u8;
                let mac_ptr = data.add(nlen);
                let mut mac = [0u8; 6];
                std::ptr::copy_nonoverlapping(mac_ptr, mac.as_mut_ptr(), 6);
                result = Some(mac);
                break;
            }
            cursor = ifa.ifa_next;
        }
        libc::freeifaddrs(ifaddrs);
        result.context("MAC address not found for interface")
    }
}

#[cfg(target_os = "linux")]
fn get_default_gateway_ipv4(iface: &str) -> Result<Ipv4Addr> {
    let content =
        std::fs::read_to_string("/proc/net/route").context("cannot read /proc/net/route")?;
    parse_linux_default_gateway_ipv4(iface, &content)
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn parse_linux_default_gateway_ipv4(iface: &str, route_table: &str) -> Result<Ipv4Addr> {
    for line in route_table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[0] != iface {
            continue;
        }
        // Destination == 00000000 means default route
        if fields[1] != "00000000" {
            continue;
        }
        let gw = u32::from_str_radix(fields[2], 16).context("invalid gateway hex")?;
        return Ok(Ipv4Addr::from(gw.to_le_bytes()));
    }
    bail!("no default gateway found for interface {}", iface)
}

#[cfg(target_os = "macos")]
fn get_default_gateway_ipv4(_iface: &str) -> Result<Ipv4Addr> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .context("failed to run route")?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(gw) = line.strip_prefix("gateway:") {
            let gw = gw.trim();
            return gw
                .parse()
                .with_context(|| format!("invalid gateway: {}", gw));
        }
    }
    bail!("no default gateway found")
}

fn get_interface_ipv6(iface: &str) -> Result<(Ipv6Addr, Ipv6Addr)> {
    use std::ffi::CString;
    let ifname = CString::new(iface)?;
    let mut link_local = None;
    let mut prefix = None;

    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            bail!("getifaddrs failed");
        }
        let mut cursor = ifaddrs;
        while !cursor.is_null() {
            let ifa = &*cursor;
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name);
            if name == ifname.as_c_str()
                && !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family as libc::c_int == libc::AF_INET6
            {
                let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                if (ip.segments()[0] & 0xffc0) == 0xfe80 {
                    link_local = Some(ip);
                } else if !ip.is_loopback() && !ip.is_multicast() {
                    prefix = Some(ip);
                }
            }
            cursor = ifa.ifa_next;
        }
        libc::freeifaddrs(ifaddrs);
    }

    select_router_advertisement_addrs(link_local, prefix)
}

fn select_router_advertisement_addrs(
    link_local: Option<Ipv6Addr>,
    prefix: Option<Ipv6Addr>,
) -> Result<(Ipv6Addr, Ipv6Addr)> {
    let ll = link_local.context("no link-local IPv6 address found")?;
    let prefix = prefix.context("no non-link-local IPv6 prefix address found")?;
    Ok((ll, prefix))
}

fn get_interface_index(iface: &str) -> Result<u32> {
    let idx = unsafe {
        let name = std::ffi::CString::new(iface)?;
        libc::if_nametoindex(name.as_ptr())
    };
    if idx == 0 {
        bail!("interface {} not found", iface);
    }
    Ok(idx)
}

// ── ARP packet construction ───────────────────────────────────────────

fn build_gratuitous_arp(src_mac: &[u8; 6], gateway_ip: Ipv4Addr) -> Vec<u8> {
    let ip = gateway_ip.octets();
    let mut pkt = Vec::with_capacity(42);

    // Ethernet header
    pkt.extend_from_slice(&[0xff; 6]); // dst: broadcast
    pkt.extend_from_slice(src_mac); // src: our MAC
    pkt.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP

    // ARP payload
    pkt.extend_from_slice(&[0x00, 0x01]); // HTYPE: Ethernet
    pkt.extend_from_slice(&[0x08, 0x00]); // PTYPE: IPv4
    pkt.push(6); // HLEN
    pkt.push(4); // PLEN
    pkt.extend_from_slice(&[0x00, 0x02]); // OPER: reply
    pkt.extend_from_slice(src_mac); // SHA: our MAC
    pkt.extend_from_slice(&ip); // SPA: gateway IP (we claim to be it)
    pkt.extend_from_slice(&[0xff; 6]); // THA: broadcast
    pkt.extend_from_slice(&ip); // TPA: gateway IP

    pkt
}

// ── RA packet construction ────────────────────────────────────────────

fn build_router_advertisement(src_mac: &[u8; 6], prefix: Ipv6Addr) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(80);

    // ICMPv6 header
    pkt.push(134); // Type: Router Advertisement
    pkt.push(0); // Code
    pkt.extend_from_slice(&[0, 0]); // Checksum (kernel computes)

    // RA fields
    pkt.push(64); // Cur Hop Limit
    pkt.push(0x08); // Flags: Prf=High (bits 3-4 = 01)
    pkt.extend_from_slice(&RA_ROUTER_LIFETIME.to_be_bytes()); // Router Lifetime
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Reachable Time
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Retrans Timer

    // Option: Source Link-Layer Address (type 1)
    pkt.push(1); // Type
    pkt.push(1); // Length (in units of 8 bytes)
    pkt.extend_from_slice(src_mac);

    // Option: Prefix Information (type 3)
    let prefix_octets = prefix.octets();
    let mut prefix_bytes = [0u8; 16];
    prefix_bytes[..8].copy_from_slice(&prefix_octets[..8]); // /64 prefix

    pkt.push(3); // Type
    pkt.push(4); // Length (32 bytes = 4 * 8)
    pkt.push(64); // Prefix Length
    pkt.push(0xc0); // Flags: L + A (on-link + autonomous)
    pkt.extend_from_slice(&2592000u32.to_be_bytes()); // Valid Lifetime: 30 days
    pkt.extend_from_slice(&604800u32.to_be_bytes()); // Preferred Lifetime: 7 days
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Reserved
    pkt.extend_from_slice(&prefix_bytes);

    pkt
}

// ── Platform-specific raw send ────────────────────────────────────────

#[cfg(target_os = "linux")]
fn send_arp_packet(iface: &str, packet: &[u8]) -> Result<()> {
    let ifindex = get_interface_index(iface)?;
    unsafe {
        let sock = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as libc::c_int,
        );
        if sock < 0 {
            bail!(
                "failed to open AF_PACKET socket: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut addr: libc::sockaddr_ll = std::mem::zeroed();
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = ifindex as i32;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);

        let ret = libc::sendto(
            sock,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        libc::close(sock);

        if ret < 0 {
            bail!("ARP sendto failed: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn send_arp_packet(iface: &str, packet: &[u8]) -> Result<()> {
    use std::ffi::CString;
    unsafe {
        let mut bpf_fd = -1i32;
        for i in 0..256 {
            let path = CString::new(format!("/dev/bpf{}", i))?;
            bpf_fd = libc::open(path.as_ptr(), libc::O_WRONLY);
            if bpf_fd >= 0 {
                break;
            }
        }
        if bpf_fd < 0 {
            bail!(
                "failed to open /dev/bpf: {}",
                std::io::Error::last_os_error()
            );
        }

        let ifname = CString::new(iface)?;
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let name_bytes = ifname.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );

        const BIOCSETIF: libc::c_ulong = 0x8020426c;
        if libc::ioctl(bpf_fd, BIOCSETIF, &ifr) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(bpf_fd);
            bail!("BIOCSETIF failed: {}", e);
        }

        let ret = libc::write(bpf_fd, packet.as_ptr() as *const libc::c_void, packet.len());
        libc::close(bpf_fd);

        if ret < 0 {
            bail!("BPF write failed: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn send_ra_packet(iface: &str, src_addr: Ipv6Addr, packet: &[u8]) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn check_syscall(ret: libc::c_int, operation: &str) -> Result<()> {
        if ret < 0 {
            bail!("{} failed: {}", operation, std::io::Error::last_os_error());
        }
        Ok(())
    }

    let ifindex = get_interface_index(iface)?;
    unsafe {
        let sock = libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6);
        if sock < 0 {
            bail!(
                "failed to open ICMPv6 socket: {}",
                std::io::Error::last_os_error()
            );
        }
        let sock = OwnedFd::from_raw_fd(sock);

        let hops: libc::c_int = 255;
        check_syscall(
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_HOPS,
                &hops as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ),
            "setting IPv6 multicast hop limit",
        )?;
        check_syscall(
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                &hops as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ),
            "setting IPv6 unicast hop limit",
        )?;
        check_syscall(
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_IF,
                &ifindex as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            ),
            "setting IPv6 multicast interface",
        )?;

        // Bind to source link-local address
        let mut bind_addr: libc::sockaddr_in6 = std::mem::zeroed();
        bind_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        bind_addr.sin6_addr.s6_addr = src_addr.octets();
        bind_addr.sin6_scope_id = ifindex;
        check_syscall(
            libc::bind(
                sock.as_raw_fd(),
                &bind_addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
            "binding RA socket to source address",
        )?;

        // Destination: ff02::1 (all-nodes multicast)
        let mut dst: libc::sockaddr_in6 = std::mem::zeroed();
        dst.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        dst.sin6_addr.s6_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets();
        dst.sin6_scope_id = ifindex;

        let ret = libc::sendto(
            sock.as_raw_fd(),
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dst as *const libc::sockaddr_in6 as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        );

        if ret < 0 {
            bail!("RA sendto failed: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

// ── Main loop ─────────────────────────────────────────────────────────

pub async fn run(iface: &str) -> Result<()> {
    let mac = get_mac_address(iface)?;
    let mac_str = mac
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");

    let gateway_ip = get_default_gateway_ipv4(iface)?;
    info!(
        "Gateway advertisement on {}: ARP spoofing {} with MAC {}",
        iface, gateway_ip, mac_str
    );

    let arp_pkt = build_gratuitous_arp(&mac, gateway_ip);

    let (link_local, global) = match get_interface_ipv6(iface) {
        Ok(addrs) => addrs,
        Err(e) => {
            warn!("IPv6 RA disabled: {}", e);
            (Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
        }
    };

    let ra_enabled = !link_local.is_unspecified();
    let ra_pkt = if ra_enabled {
        let pkt = build_router_advertisement(&mac, global);
        info!(
            "Router Advertisement enabled: prefix {}::/64, src {}",
            global.segments()[..4]
                .iter()
                .map(|s| format!("{:x}", s))
                .collect::<Vec<_>>()
                .join(":"),
            link_local
        );
        Some(pkt)
    } else {
        None
    };

    let mut tick = interval(ARP_INTERVAL);
    let mut tick_count: u64 = 0;

    loop {
        tick.tick().await;
        tick_count += 1;

        if let Err(e) = send_arp_packet(iface, &arp_pkt) {
            warn!("ARP broadcast failed: {:#}", e);
        } else {
            debug!("ARP: {} is-at {}", gateway_ip, mac_str);
        }

        if let Some(ref ra) = ra_pkt {
            if tick_count.is_multiple_of(RA_INTERVAL_TICKS) {
                if let Err(e) = send_ra_packet(iface, link_local, ra) {
                    warn!("RA broadcast failed: {:#}", e);
                } else {
                    debug!("RA: sent router advertisement on {}", iface);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("not-a-mac").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee:zz").is_err());
    }

    #[test]
    fn test_build_gratuitous_arp() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gw = Ipv4Addr::new(192, 168, 0, 1);
        let pkt = build_gratuitous_arp(&mac, gw);

        assert_eq!(pkt.len(), 42);
        // Ethernet dst = broadcast
        assert_eq!(&pkt[0..6], &[0xff; 6]);
        // Ethernet src = our MAC
        assert_eq!(&pkt[6..12], &mac);
        // EtherType = ARP
        assert_eq!(&pkt[12..14], &[0x08, 0x06]);
        // ARP operation = reply (2)
        assert_eq!(&pkt[20..22], &[0x00, 0x02]);
        // SHA = our MAC
        assert_eq!(&pkt[22..28], &mac);
        // SPA = gateway IP
        assert_eq!(&pkt[28..32], &[192, 168, 0, 1]);
    }

    #[test]
    fn test_build_router_advertisement() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
        let pkt = build_router_advertisement(&mac, prefix);

        // ICMPv6 type = 134 (RA)
        assert_eq!(pkt[0], 134);
        assert_eq!(pkt[1], 0);
        // Cur Hop Limit
        assert_eq!(pkt[4], 64);
        // Flags: Prf=High
        assert_eq!(pkt[5] & 0x18, 0x08);
        // Source Link-Layer option type
        assert_eq!(pkt[16], 1);
        assert_eq!(&pkt[18..24], &mac);
        // Prefix Info option type
        assert_eq!(pkt[24], 3);
        // Prefix length
        assert_eq!(pkt[26], 64);
        // Only /64 prefix (first 8 bytes of the address, rest zeroed)
        assert_eq!(
            &pkt[40..48],
            &[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(&pkt[48..56], &[0; 8]);
    }

    #[test]
    fn test_parse_linux_default_gateway_ipv4() {
        let route_table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
wlan0\t00000000\tFE01A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n";

        assert_eq!(
            parse_linux_default_gateway_ipv4("eth0", route_table).unwrap(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(
            parse_linux_default_gateway_ipv4("wlan0", route_table).unwrap(),
            Ipv4Addr::new(192, 168, 1, 254)
        );
    }

    #[test]
    fn test_select_router_advertisement_addrs_requires_prefix() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        let result = select_router_advertisement_addrs(Some(link_local), None);

        assert!(result.is_err());
    }

    #[test]
    fn test_select_router_advertisement_addrs_uses_non_link_local_prefix() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        let prefix = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1);

        assert_eq!(
            select_router_advertisement_addrs(Some(link_local), Some(prefix)).unwrap(),
            (link_local, prefix)
        );
    }

    #[test]
    fn test_parse_linux_default_gateway_ipv4_ignores_non_default_route() {
        let route_table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

        assert!(parse_linux_default_gateway_ipv4("eth0", route_table).is_err());
    }

    #[test]
    fn test_get_interface_index_loopback() {
        #[cfg(target_os = "macos")]
        let idx = get_interface_index("lo0");
        #[cfg(target_os = "linux")]
        let idx = get_interface_index("lo");
        assert!(idx.is_ok());
        assert!(idx.unwrap() > 0);
    }

    #[test]
    fn test_get_interface_index_nonexistent() {
        assert!(get_interface_index("nonexistent_xyz").is_err());
    }
}
