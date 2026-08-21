//! Connection accounting for the public stratum listener (lab #544).
//!
//! Thread-per-connection makes the cap load-bearing: each admitted peer is
//! an OS thread. Refusals are named tokens and atomics, so a flood and an
//! idle pool cannot produce the same silence.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Public-endpoint default. 64 threads × a 2 MiB stack is ~128 MiB in a
/// 2g container, with headroom for RandomX. Not a measured optimum: T2
/// will not have 64 miners when this lands, and a flood of 65 is the
/// thing the cap exists to name.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 64;
/// One peer occupies at most one eighth of [`DEFAULT_MAX_CONNECTIONS`].
/// Unset `max_connections_per_ip` derives as `max(1, max_connections / this)`.
pub const PER_IP_DIVISOR: u32 = 8;
/// Stratum JSON-RPC lines are hundreds of bytes. 4 KiB is ~10× a submit.
pub const DEFAULT_MAX_LINE_BYTES: usize = 4096;
/// Wall-clock to finish one line after its first byte. Distinct from the
/// 100 ms per-read timeout, which exists to drain the job outbox.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 10_000;

pub const REASON_CONNECTION_CAP: &str = "connection-cap-reached";
pub const REASON_PER_IP: &str = "per-ip-connection-cap-reached";
pub const REASON_LINE_TOO_LONG: &str = "line-too-long";
pub const REASON_REQUEST_TIMEOUT: &str = "request-timeout";
pub const REASON_CONNECTION_TIMEOUT: &str = "connection-timeout";

/// Bounds the accept loop and each connection thread consult.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenLimits {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub max_line_bytes: usize,
    pub request_timeout: Duration,
    pub connection_timeout: Duration,
}

impl ListenLimits {
    /// Production defaults, with per-IP and connection timeout derived.
    pub fn public_endpoint() -> Self {
        Self::from_parts(
            DEFAULT_MAX_CONNECTIONS,
            None,
            DEFAULT_MAX_LINE_BYTES,
            Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            None,
        )
    }

    /// `max_connections_per_ip` unset → `max(1, max_connections / PER_IP_DIVISOR)`.
    /// `connection_timeout` unset → `request_timeout`.
    pub fn from_parts(
        max_connections: u32,
        max_connections_per_ip: Option<u32>,
        max_line_bytes: usize,
        request_timeout: Duration,
        connection_timeout: Option<Duration>,
    ) -> Self {
        let max_connections = max_connections.max(1);
        let max_connections_per_ip = max_connections_per_ip
            .unwrap_or_else(|| (max_connections / PER_IP_DIVISOR).max(1))
            .max(1);
        let request_timeout = request_timeout.max(Duration::from_millis(1));
        let connection_timeout = connection_timeout
            .unwrap_or(request_timeout)
            .max(Duration::from_millis(1));
        Self {
            max_connections,
            max_connections_per_ip,
            max_line_bytes: max_line_bytes.max(1),
            request_timeout,
            connection_timeout,
        }
    }
}

impl Default for ListenLimits {
    fn default() -> Self {
        Self::public_endpoint()
    }
}

/// Why [`ConnGuard::admit`] refused a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitError {
    ConnectionCap,
    PerIpCap,
}

impl AdmitError {
    pub fn reason(self, limits: &ListenLimits) -> String {
        match self {
            AdmitError::ConnectionCap => {
                format!("{REASON_CONNECTION_CAP} cap={}", limits.max_connections)
            }
            AdmitError::PerIpCap => {
                format!("{REASON_PER_IP} cap={}", limits.max_connections_per_ip)
            }
        }
    }

    pub fn token(self) -> &'static str {
        match self {
            AdmitError::ConnectionCap => REASON_CONNECTION_CAP,
            AdmitError::PerIpCap => REASON_PER_IP,
        }
    }
}

/// Operator snapshot. Atomically-read counters; `live` / `live_ips` from the
/// mutex so they can disagree with a counter by at most one in-flight admit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardSnapshot {
    pub live: u32,
    pub live_ips: u32,
    pub admitted: u64,
    pub refused_connection_cap: u64,
    pub refused_per_ip: u64,
    pub refused_line_too_long: u64,
    pub refused_request_timeout: u64,
    pub refused_connection_timeout: u64,
}

impl GuardSnapshot {
    /// Compact fields for a journal line. One grep family: `refused_cap=`
    /// is the flood, `live=0 refused_cap=0` is nobody mining.
    pub fn journal_fields(&self) -> String {
        format!(
            "live={} live_ips={} admitted={} refused_cap={} refused_per_ip={} refused_line={} refused_request_timeout={} refused_connection_timeout={}",
            self.live,
            self.live_ips,
            self.admitted,
            self.refused_connection_cap,
            self.refused_per_ip,
            self.refused_line_too_long,
            self.refused_request_timeout,
            self.refused_connection_timeout
        )
    }
}

#[derive(Debug)]
struct Inner {
    live: u32,
    per_ip: HashMap<IpAddr, u32>,
}

/// Shared by the accept loop and every connection thread.
#[derive(Debug)]
pub struct ConnGuard {
    limits: ListenLimits,
    inner: Mutex<Inner>,
    admitted: AtomicU64,
    refused_connection_cap: AtomicU64,
    refused_per_ip: AtomicU64,
    refused_line_too_long: AtomicU64,
    refused_request_timeout: AtomicU64,
    refused_connection_timeout: AtomicU64,
}

impl ConnGuard {
    pub fn new(limits: ListenLimits) -> Self {
        Self {
            limits,
            inner: Mutex::new(Inner {
                live: 0,
                per_ip: HashMap::new(),
            }),
            admitted: AtomicU64::new(0),
            refused_connection_cap: AtomicU64::new(0),
            refused_per_ip: AtomicU64::new(0),
            refused_line_too_long: AtomicU64::new(0),
            refused_request_timeout: AtomicU64::new(0),
            refused_connection_timeout: AtomicU64::new(0),
        }
    }

    pub fn limits(&self) -> &ListenLimits {
        &self.limits
    }

    /// Admit one connection. The returned slot releases the accounting on drop,
    /// including panic unwind — a leaked slot would be a silent cap shrink.
    ///
    /// Takes `&Arc<Self>` so the slot can move onto the connection thread.
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnSlot, AdmitError> {
        let ip = canon_ip(ip);
        let mut g = self.inner.lock().expect("conn-guard mutex");
        if g.live >= self.limits.max_connections {
            self.refused_connection_cap.fetch_add(1, Ordering::SeqCst);
            return Err(AdmitError::ConnectionCap);
        }
        let held = g.per_ip.get(&ip).copied().unwrap_or(0);
        if held >= self.limits.max_connections_per_ip {
            self.refused_per_ip.fetch_add(1, Ordering::SeqCst);
            return Err(AdmitError::PerIpCap);
        }
        g.live += 1;
        *g.per_ip.entry(ip).or_insert(0) += 1;
        self.admitted.fetch_add(1, Ordering::SeqCst);
        drop(g);
        Ok(ConnSlot {
            guard: Arc::clone(self),
            ip,
            released: false,
        })
    }

    pub fn record_line_too_long(&self) {
        self.refused_line_too_long.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_request_timeout(&self) {
        self.refused_request_timeout.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_connection_timeout(&self) {
        self.refused_connection_timeout
            .fetch_add(1, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> GuardSnapshot {
        let g = self.inner.lock().expect("conn-guard mutex");
        GuardSnapshot {
            live: g.live,
            live_ips: g.per_ip.len() as u32,
            admitted: self.admitted.load(Ordering::SeqCst),
            refused_connection_cap: self.refused_connection_cap.load(Ordering::SeqCst),
            refused_per_ip: self.refused_per_ip.load(Ordering::SeqCst),
            refused_line_too_long: self.refused_line_too_long.load(Ordering::SeqCst),
            refused_request_timeout: self.refused_request_timeout.load(Ordering::SeqCst),
            refused_connection_timeout: self.refused_connection_timeout.load(Ordering::SeqCst),
        }
    }

    fn release(&self, ip: IpAddr) {
        let mut g = self.inner.lock().expect("conn-guard mutex");
        g.live = g.live.saturating_sub(1);
        if let Some(n) = g.per_ip.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.per_ip.remove(&ip);
            }
        }
    }
}

/// RAII ticket from [`ConnGuard::admit`]. Dropping it is what opens the slot.
#[derive(Debug)]
pub struct ConnSlot {
    guard: Arc<ConnGuard>,
    ip: IpAddr,
    released: bool,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            self.guard.release(self.ip);
        }
    }
}

/// v4-mapped v6 (`::ffff:a.b.c.d`) shares the v4 bucket. Otherwise one IPv4
/// peer occupying both families would double its per-IP allowance.
pub fn canon_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::thread;

    fn tight() -> Arc<ConnGuard> {
        Arc::new(ConnGuard::new(ListenLimits::from_parts(
            2,
            Some(2),
            64,
            Duration::from_secs(1),
            None,
        )))
    }

    #[test]
    fn per_ip_default_is_one_eighth_of_the_cap() {
        let l = ListenLimits::from_parts(64, None, 4096, Duration::from_secs(10), None);
        assert_eq!(l.max_connections, 64);
        assert_eq!(l.max_connections_per_ip, 8);
        let small = ListenLimits::from_parts(4, None, 4096, Duration::from_secs(10), None);
        assert_eq!(small.max_connections_per_ip, 1, "4/8 floors to 1, never 0");
        let explicit = ListenLimits::from_parts(64, Some(3), 4096, Duration::from_secs(10), None);
        assert_eq!(explicit.max_connections_per_ip, 3);
    }

    #[test]
    fn connection_timeout_default_tracks_request_timeout() {
        let l = ListenLimits::from_parts(64, None, 4096, Duration::from_millis(2500), None);
        assert_eq!(l.connection_timeout, Duration::from_millis(2500));
        let explicit = ListenLimits::from_parts(
            64,
            None,
            4096,
            Duration::from_millis(2500),
            Some(Duration::from_millis(8000)),
        );
        assert_eq!(explicit.connection_timeout, Duration::from_millis(8000));
    }

    #[test]
    fn cap_refuses_the_third_and_counts_it() {
        let g = tight();
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let _s1 = g.admit(a.into()).unwrap();
        let _s2 = g.admit(Ipv4Addr::new(10, 0, 0, 2).into()).unwrap();
        let err = g.admit(Ipv4Addr::new(10, 0, 0, 3).into()).unwrap_err();
        assert_eq!(err, AdmitError::ConnectionCap);
        assert!(err.reason(g.limits()).starts_with(REASON_CONNECTION_CAP));
        let snap = g.snapshot();
        assert_eq!(snap.live, 2);
        assert_eq!(snap.admitted, 2);
        assert_eq!(snap.refused_connection_cap, 1);
        assert_eq!(snap.refused_per_ip, 0);
    }

    #[test]
    fn per_ip_cap_is_its_own_counter() {
        let g = Arc::new(ConnGuard::new(ListenLimits::from_parts(
            8,
            Some(1),
            64,
            Duration::from_secs(1),
            None,
        )));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let _s1 = g.admit(ip).unwrap();
        let err = g.admit(ip).unwrap_err();
        assert_eq!(err, AdmitError::PerIpCap);
        assert!(err.reason(g.limits()).starts_with(REASON_PER_IP));
        // A different IP still fits under the global cap.
        let _s2 = g.admit(Ipv4Addr::new(10, 0, 0, 10).into()).unwrap();
        let snap = g.snapshot();
        assert_eq!(snap.live, 2);
        assert_eq!(snap.refused_per_ip, 1);
        assert_eq!(snap.refused_connection_cap, 0);
    }

    #[test]
    fn v4_mapped_v6_shares_the_v4_bucket() {
        let g = Arc::new(ConnGuard::new(ListenLimits::from_parts(
            8,
            Some(1),
            64,
            Duration::from_secs(1),
            None,
        )));
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201));
        assert_eq!(canon_ip(v6), v4);
        let _s1 = g.admit(v4).unwrap();
        assert_eq!(g.admit(v6).unwrap_err(), AdmitError::PerIpCap);
    }

    #[test]
    fn drop_releases_the_slot() {
        let g = tight();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        {
            let _s1 = g.admit(ip).unwrap();
            let _s2 = g.admit(ip).unwrap();
            assert_eq!(g.snapshot().live, 2);
        }
        assert_eq!(g.snapshot().live, 0);
        assert_eq!(g.snapshot().live_ips, 0);
        let _again = g.admit(ip).unwrap();
        assert_eq!(g.snapshot().live, 1);
    }

    #[test]
    fn slot_release_is_visible_across_threads() {
        let g = tight();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let g1 = Arc::clone(&g);
        let h = thread::spawn(move || {
            let _s = g1.admit(ip).unwrap();
            thread::sleep(Duration::from_millis(30));
        });
        h.join().unwrap();
        assert_eq!(g.snapshot().live, 0);
        assert_eq!(g.snapshot().admitted, 1);
    }
}
