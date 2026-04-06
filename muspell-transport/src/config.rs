//! Transport layer configuration.

use muspell_proto::NodeCapabilities;
use std::time::Duration;

/// The ALPN protocol identifier for Muspell.
///
/// Both sides of every QUIC connection MUST register this ALPN on their
/// endpoint. It is the gate that distinguishes Muspell connections from
/// any other protocol running over the same QUIC port.
pub const ALPN: &[u8] = b"muspell/0.1";

/// Configuration for a [`MuspellEndpoint`] and the connections it creates.
///
/// ## Defaults
///
/// The defaults are deliberately conservative, suitable for a daemon
/// running on a residential internet connection. High-throughput nodes
/// (relays, storage nodes) should increase `max_frame_size` and decrease
/// `handshake_timeout`.
///
/// [`MuspellEndpoint`]: crate::endpoint::MuspellEndpoint
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// Maximum CBOR-encoded frame size in bytes.
    ///
    /// Frames larger than this are rejected with `FrameTooLarge` to prevent
    /// memory exhaustion from a misbehaving peer. Default: 4 MiB.
    pub max_frame_size: u32,

    /// Maximum time to wait for the `HelloAck` to arrive after sending
    /// our `Hello`. If the timeout expires, the connection is closed.
    /// Default: 10 seconds.
    pub handshake_timeout: Duration,

    /// Interval at which `Ping` frames are sent to verify the connection
    /// is alive. Default: 30 seconds.
    ///
    /// Set to `None` to disable keepalives entirely (not recommended for
    /// connections that cross NAT devices).
    pub keepalive_interval: Option<Duration>,

    /// Time to wait for a `Pong` response before treating the connection
    /// as dead and closing it. Default: 10 seconds.
    pub keepalive_timeout: Duration,

    /// The roles this node advertises in its `Hello` frame.
    pub local_capabilities: NodeCapabilities,

    /// Human-readable user agent string, embedded in `Hello`.
    /// Format convention: `"muspell-<component>/<version> (<os>/<arch>)"`.
    pub user_agent: Option<String>,

    /// How long to keep a signed `IdentityBinding` valid.
    /// Used when calling `sign_binding` during the handshake.
    /// Default: 24 hours.
    pub binding_validity: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_frame_size:     4 * 1024 * 1024, // 4 MiB
            handshake_timeout:  Duration::from_secs(10),
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_timeout:  Duration::from_secs(10),
            local_capabilities: NodeCapabilities::none(),
            user_agent:         None,
            binding_validity:   Duration::from_secs(86_400), // 24 h
        }
    }
}

impl TransportConfig {
    /// Create a new config with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the maximum frame size.
    #[must_use]
    pub fn with_max_frame_size(mut self, bytes: u32) -> Self {
        self.max_frame_size = bytes;
        self
    }

    /// Override the handshake timeout.
    #[must_use]
    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    /// Set the keepalive interval. Pass `None` to disable.
    #[must_use]
    pub fn with_keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.keepalive_interval = interval;
        self
    }

    /// Set the local node capabilities advertised in the handshake.
    #[must_use]
    pub fn with_capabilities(mut self, caps: NodeCapabilities) -> Self {
        self.local_capabilities = caps;
        self
    }

    /// Set the user-agent string.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Set the identity binding validity duration.
    #[must_use]
    pub fn with_binding_validity(mut self, d: Duration) -> Self {
        self.binding_validity = d;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_sane() {
        let cfg = TransportConfig::default();
        assert_eq!(cfg.max_frame_size, 4 * 1024 * 1024);
        assert!(cfg.handshake_timeout.as_secs() > 0);
        assert!(cfg.keepalive_interval.is_some());
    }

    #[test]
    fn config_builder_chain() {
        let cfg = TransportConfig::new()
            .with_max_frame_size(1024)
            .with_handshake_timeout(Duration::from_secs(5))
            .with_keepalive_interval(None)
            .with_user_agent("muspell-test/0.1");

        assert_eq!(cfg.max_frame_size, 1024);
        assert_eq!(cfg.handshake_timeout, Duration::from_secs(5));
        assert!(cfg.keepalive_interval.is_none());
        assert_eq!(cfg.user_agent.as_deref(), Some("muspell-test/0.1"));
    }

    #[test]
    fn alpn_is_non_empty() {
        assert!(!ALPN.is_empty());
        // Must be valid UTF-8 (iroh validates this).
        assert!(std::str::from_utf8(ALPN).is_ok());
    }
}
