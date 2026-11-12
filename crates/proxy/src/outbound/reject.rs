//! The REJECT outbound connector.
//!
//! This module performs no I/O. It exists so the daemon can route a matched
//! REJECT rule through the same [`crate::outbound::OutboundStream`] dispatch
//! as real connectors.

use crate::outbound::OutboundStream;

/// Return a rejected outbound stream (no connection is made).
///
/// The caller should drop the inbound connection without sending data; the
/// returned [`OutboundStream::Rejected`] carries no socket.
pub fn reject() -> OutboundStream {
    OutboundStream::Rejected
}
