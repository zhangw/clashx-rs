use crate::outbound::OutboundStream;

/// Return a rejected outbound stream (no connection is made).
pub fn reject() -> OutboundStream {
    OutboundStream::Rejected
}
