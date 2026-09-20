// Copyright (c) 2023 Discernible IO. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[derive(Debug)]
pub enum WireGuardError {
    DestinationBufferTooSmall,
    IncorrectPacketLength,
    UnexpectedPacket,
    WrongPacketType,
    WrongSessionIndex,
    WrongKey,
    InvalidTai64nTimestamp,
    WrongTai64nTimestamp,
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    LockFailed,
    ConnectionExpired,
    UnderLoad,
    PeerEd25519PublicKeyParsingFailure,
    PeerEd25519SignatureVerificationFailure,
    PeerEd25519SignatureParsingFailure,
    ServiceProviderEd25519SignatureVerificationSuccess,
    ServiceProviderEd25519SignatureVerificationFailure,
    ServiceProviderEd25519SignatureParsingFailure,
    ServiceProviderEd25519PublicKeyParsingFailure,
    ServiceProviderEd25519SignatureFetchingFailure,
    PeerEd25519RoditMissing,
}
