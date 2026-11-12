//! Inbound protocol handling, outbound connectors, and the shared relay.
//!
//! Entry points:
//!
//! - [`inbound::detect_and_handle`] sniffs the first byte of an accepted
//!   connection, runs the SOCKS5 or HTTP proxy handshake, and returns the
//!   target plus any bytes that were read ahead ([`inbound::InboundResult`]).
//! - [`outbound`] dials that target through DIRECT, Trojan, or SOCKS5 and
//!   returns an [`outbound::OutboundStream`]. A matched REJECT rule is handled
//!   by the daemon before a connector runs.
//! - [`relay::relay_with_policy`] forwards bytes between the inbound and
//!   outbound streams while enforcing inactive-connection reclamation.
//!
//! Invariants a caller must uphold:
//!
//! - Handshakes are bounded by [`timeout::HANDSHAKE_TIMEOUT`] and outbound
//!   setup by [`timeout::CONNECT_TIMEOUT`] or
//!   [`timeout::PROXY_CONNECT_TIMEOUT`]; callers should not add an outer
//!   timeout that changes those semantics.
//! - Bytes in [`inbound::InboundResult::initial_data`] were consumed from the
//!   inbound socket and must be written to the outbound stream before the
//!   relay starts, otherwise early TLS/HTTP bytes are lost.
//! - Relay lifetime is activity-based, never a total-duration cap. The
//!   resource accounting that pairs with it is described in
//!   [`docs/resource-budget.md`](../../../docs/resource-budget.md).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unchecked_time_subtraction
    )
)]

pub mod inbound;
pub mod outbound;
pub mod relay;
pub mod socket;
pub mod timeout;
