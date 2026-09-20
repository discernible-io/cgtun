// Copyright (c) 2023 Discernible IO. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod rate_limiter;
mod session;
mod timers;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::noise::constants::{BLOCKCHAIN_NETWORK,SMART_CONTRACT};
use crate::x25519;
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use ed25519_dalek::{PublicKey,Verifier,Signature};
use hex::FromHex;
use regex::Regex;
use base64::decode as base64decode;
use chrono::{NaiveDate,NaiveDateTime,NaiveTime};
// Moving timestamp function
use reqwest::blocking::Client;
use serde_json::Value;
use serde::Serialize;
use serde::Deserialize;
use base64::URL_SAFE_NO_PAD;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

const KEY_LEN: usize = 32;

pub mod constants {
    // Define the smart contract account (the Issuer) and the blockchain environment and 'global constants'
    pub const SMART_CONTRACT: &str = "rodit-org.near";
    pub const BLOCKCHAIN_NETWORK: &str = "."; // IMPORTANT: Values here must be either ".testnet." for testnet or "." for mainnet;
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rodit {
    pub token_id: String,
    pub owner_id: String,
    pub metadata: RoditMetadata,
    pub approved_account_ids: serde_json::Value,
    pub royalty: serde_json::Value,
}


impl Default for Rodit {
    fn default() -> Self {
        Rodit {
            token_id: String::default(),
            owner_id: String::default(),
            metadata: RoditMetadata::default(),
            approved_account_ids: serde_json::Value::Null,
            royalty: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RoditMetadata {
    pub issuername: String,
    pub description: String,
    pub notafter: String,
    pub notbefore: String,
    pub cidrblock: String,
    pub listenport: String,
    pub dns: String,
    // pub postup: String,
    // pub postdown: String,
    pub allowedips: String,
    pub subjectuniqueidentifierurl: String,
    pub serviceproviderid: String,
    pub serviceprovidersignature: String,
    // pub kbpersecond: String,
}

impl Default for RoditMetadata {
    fn default() -> Self {
        RoditMetadata {
            issuername: String::default(),
            description: String::default(),
            notafter: String::default(),
            notbefore: String::default(),
            cidrblock: String::default(),
            listenport: String::default(),
            dns: String::default(),
            // postup: String::default(),
            // postdown: String::default(),
            allowedips: String::default(),
            subjectuniqueidentifierurl: String::default(),
            serviceproviderid: String::default(),
            serviceprovidersignature: String::default(),
            // kbpersecond: String::default(),
        }
    }
}

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The Own serviceprovider ID to check if it matches upon handshake
    // CG: The following variable is necessary if mutual checks are performed for every handshake and not only the initial one
    own_serviceproviderid: String,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
}

type MessageType = u32;
const HANDSHAKE_INIT_CONSTANT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;
pub const RODIT_ID_SZ:usize = 128;
pub const RODIT_ID_SIGNATURE_SZ:usize = 64;
pub const RODIT_ID_PK_SZ:usize = 32;

// These sizes are increased by RODIT_ID_SZ + 64 bytes to accommodate for the rodit_id and signature of the same
const HANDSHAKE_INIT_SZ: usize = 148+RODIT_ID_SZ+RODIT_ID_SIGNATURE_SZ;
const HANDSHAKE_RESP_SZ: usize = 92+RODIT_ID_SZ+RODIT_ID_SIGNATURE_SZ;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

#[derive(Debug,Copy, Clone)]
pub struct HandshakeInit<'a> {
    sender_session_index: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
    pub rodit_id: &'a [u8; RODIT_ID_SZ],
    pub rodit_id_signature: &'a [u8; RODIT_ID_SIGNATURE_SZ],
}

#[derive(Debug,Copy, Clone)]
pub struct HandshakeResponse<'a> {
    sender_session_index: u32,
    pub receiver_session_index: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
    rodit_id: &'a [u8; RODIT_ID_SZ],
    rodit_id_signature: &'a [u8; RODIT_ID_SIGNATURE_SZ],
}

#[derive(Debug,Copy,Clone)]
pub struct PacketCookieReply<'a> {
    pub receiver_session_index: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug,Copy,Clone)]
pub struct PacketData<'a> {
    pub receiver_session_index: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug,Copy,Clone)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

impl Tunn {
    #[inline(always)]
    pub fn consume_incoming_packet(src: &[u8]) -> Result<Packet, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
                (HANDSHAKE_INIT_CONSTANT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                //} TOTAL SIZE WAS 148 (with MAC), now plus 128
                sender_session_index: u32::from_le_bytes(src[4..8].try_into().unwrap()), // SIZE u32 = 4 times 8, 8-4 = 4 bytes
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40]) // SIZE u8;32, 40-8 = 32 bytes
                    .expect("Error: Failure checking packet field length"),
                encrypted_static: &src[40..88], // SIZE u8;32, 88-40 = 48 bytes, seems too big for the spec u8 encrypted_static[AEAD_LEN(32)]
                encrypted_timestamp: &src[88..116], // SIZE u8;12, 116-88 = 28 bytes, seems too big for the spec u8 encrypted_timestamp[AEAD_LEN(12)]
                rodit_id: <&[u8; RODIT_ID_SZ] as TryFrom<&[u8]>>::try_from(&src[116..244])
                    .expect("Error: Failure checking packet field length"), // SIZE u8;128, 244-116 = 128 bytes
                rodit_id_signature: <&[u8; RODIT_ID_SIGNATURE_SZ] as TryFrom<&[u8]>>::try_from(&src[244..308])
                    .expect("Error: Failure checking packet field length"), // SIZE u8;64, 308-244 = 64 bytes
                }),
                (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                //} TOTAL SIZE WAS 92 (with MAC), now plus 128
                sender_session_index: u32::from_le_bytes(src[4..8].try_into().unwrap()), // SIZE u32 = 4 times 8, 8-4 = 4 bytes
                receiver_session_index: u32::from_le_bytes(src[8..12].try_into().unwrap()), // SIZE u32 = 4 times 8, 12-8 = 4 bytes
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44]) // SIZE u8;32, 40-8 = 32 bytes
                    .expect("Error: Failure checking packet field length"),
                encrypted_nothing: &src[44..60], // SIZE 60-44 = 16 bytes but u8 encrypted_nothing[AEAD_LEN(0)]
                rodit_id: <&[u8; RODIT_ID_SZ] as TryFrom<&[u8]>>::try_from(&src[60..188])
                    .expect("Error: Failure checking packet field length"), // SIZE u8;64, 188-60 = 128 bytes
                rodit_id_signature: <&[u8; RODIT_ID_SIGNATURE_SZ] as TryFrom<&[u8]>>::try_from(&src[188..252])
                    .expect("Error: Failure checking packet field length"), // SIZE u8;64, 252-188 = 64 bytes
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_session_index: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=std::usize::MAX) => Packet::PacketData(PacketData {
                receiver_session_index: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            }),
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        string_rodit_id: String,
        serviceproviderid: String,
        rodit_id_signature: [u8;RODIT_ID_SIGNATURE_SZ],
        persistent_keepalive: Option<u16>,
        session_index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Result<Self, &'static str> {
        let static_public = x25519::PublicKey::from(&static_private);

        // Copying the rodit_id to the Tunn safely
        let bytes_rodit_id = string_rodit_id.as_bytes();
        let mut rodit_id: [u8;RODIT_ID_SZ] = [0;RODIT_ID_SZ];
        let rodit_length = bytes_rodit_id.len().min(rodit_id.len()-1);
        rodit_id[..rodit_length].copy_from_slice(&bytes_rodit_id[..rodit_length]);
        rodit_id[rodit_length] = 0;

        let tunn = Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                session_index << 8,
                preshared_key,
                rodit_id,
                rodit_id_signature,
            )
            .map_err(|_| "Error: Invalid parameters")?,
            own_serviceproviderid: serviceproviderid,
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),
            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none()),
            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),
        };

        Ok(tunn)
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        own_staticsecret_private_key: x25519::StaticSecret,
        own_publickey_public_key: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&own_publickey_public_key, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .set_static_private(own_staticsecret_private_key, own_publickey_public_key);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // Send the packet using an established session
            let packet = session.produce_packet_data(src, dst);
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            return TunnResult::WriteToNetwork(packet);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.produce_handshake_initiation(dst, false)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .verify_packet(src_addr, datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return TunnResult::WriteToNetwork(&mut dst[..cookie.len()]);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.consume_verified_packet(packet, dst)
    }

    pub(crate) fn consume_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.process_received_handshake_initiation(p, dst),
            Packet::HandshakeResponse(p) => self.process_received_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.consume_cookie_reply(p),
            Packet::PacketData(p) => self.consume_data(p, dst),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn process_received_handshake_initiation<'a>(
        &mut self,
        peer_handshake_init: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Info: Received handshake_initiation",
            sender_session_index = peer_handshake_init.sender_session_index
        );
        let peer_static_public: [u8; KEY_LEN] = [0; KEY_LEN];
        let (packet, session) = self.handshake.consume_received_handshake_initiation(peer_handshake_init,dst,peer_static_public)?;

        // Beginning of Peer RODiT verification
        /*
        let peer_slice_rodtid: &[u8] = &peer_handshake_init.rodit_id[..];
        let _peer_string_rodtid: &str = std::str::from_utf8(peer_slice_rodtid)
        .expect("Error: Failed to convert byte slice to string")
        .trim_end_matches('\0');

        let evaluation = verify_hasrodit_getit(*peer_handshake_init.rodit_id ,*peer_handshake_init.rodit_id_signature);
        if let Ok((verification_result, rodt)) = evaluation {
            if verification_result
                && verify_rodit_isamatch(self.own_serviceproviderid.clone(),
                    rodt.metadata.serviceprovidersignature.clone(),
                    *peer_handshake_init.rodit_id)
                && verify_rodit_islive(rodt.metadata.notafter,rodt.metadata.notbefore)
                && verify_rodit_isactive(rodt.token_id,rodt.metadata.subjectuniqueidentifierurl.clone())
                && verify_rodit_smartcontract_istrusted(rodt.metadata.subjectuniqueidentifierurl.clone()) {
                    tracing::info!("Info Peer is trusted in handshake initiation");
            }
            else {
                    tracing::error!("Error: Peer is not trusted in handshake initiation");
                    return Err(WireGuardError::PeerEd25519SignatureVerificationFailure);
            }
        }
        */

        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator
        tracing::trace!(message = "Info: Sending handshake_response", own_index = index);
        Ok(TunnResult::WriteToNetwork(packet))
    }

    fn process_received_handshake_response<'a>(
        &mut self,
        peer_handshake_response: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Info: Received peer_handshake_response",
            own_index = peer_handshake_response.receiver_session_index,
            sender_session_index = peer_handshake_response.sender_session_index
        );

        let session = self.handshake.consume_received_handshake_response(peer_handshake_response)?;

        // Beginning of Peer RODiT verification
        /*
        let peer_slice_rodtid: &[u8] = &peer_handshake_response.rodit_id[..];
        let _peer_string_rodtid: &str = std::str::from_utf8(peer_slice_rodtid)
        .expect("Error: Failed to convert byte slice to string")
        .trim_end_matches('\0');

        let evaluation = verify_hasrodit_getit(*peer_handshake_response.rodit_id ,*peer_handshake_response.rodit_id_signature);
        if let Ok((verification_result, rodt)) = evaluation {
            if verification_result
                && verify_rodit_isamatch(self.own_serviceproviderid.clone(),
                    rodt.metadata.serviceprovidersignature.clone(),
                    *peer_handshake_response.rodit_id)
                && verify_rodit_islive(rodt.metadata.notafter,rodt.metadata.notbefore)
                && verify_rodit_isactive(rodt.token_id,rodt.metadata.subjectuniqueidentifierurl.clone())
                && verify_rodit_smartcontract_istrusted(rodt.metadata.subjectuniqueidentifierurl.clone()){
                    tracing::info!("Info Peer is trusted in handshake response");
            }
            else {
                tracing::error!("Error: Peer is not trusted in handshake response");
                return Err(WireGuardError::PeerEd25519SignatureVerificationFailure);
            }
        } else {
            tracing::error!("Error: Fetching RODiT with verify_hasrodit_getit in handshake response");
        }
        */

        let keepalive_packet = session.produce_packet_data(&[], dst);
        // Store new session in ring buffer
        let local_index = session.local_index();
        let index = local_index % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(local_index);

        tracing::info!("Info: Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    fn consume_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Info: Received cookie_reply",
            own_index = p.receiver_session_index
        );

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        tracing::info!("Info: Cookie set");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_index: usize) {
        let current_index = self.current;
        if current_index == new_index {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[current_index % N_SESSIONS].is_none()
            || self.timers.session_timers[new_index % N_SESSIONS]
                >= self.timers.session_timers[current_index % N_SESSIONS]
        {
            self.current = new_index;
            tracing::debug!(message = "Info: New session", session = new_index);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn consume_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let receiving_index = packet.receiver_session_index as usize;
        let idx = receiving_index % N_SESSIONS;

        // Obtain the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "Error: No current session available", sender_session_index = receiving_index);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(receiving_index);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn produce_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        match self.handshake.produce_handshake_initiation(dst) {
            Ok(packet) => {
                tracing::info!("Info: Sending handshake_initiation");

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                TunnResult::WriteToNetwork(packet)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an Error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Obtain a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On Error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    fn estimate_loss(&self) -> f32 {
        let session_index = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_index.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.duration_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

    use super::*;
    use rand_core::{OsRng, RngCore};

    fn produce_two_tuns() -> (Tunn, Tunn) {
        let own_staticsecret_private_key = x25519::StaticSecret::random_from_rng(OsRng);
        let own_publickey_public_key = x25519::PublicKey::from(&own_staticsecret_private_key);
        let my_index = OsRng.next_u32();

        let their_staticsecret_private_key = x25519::StaticSecret::random_from_rng(OsRng);
        let their_publickey_public_key = x25519::PublicKey::from(&their_secret_key);
        let their_index = OsRng.next_u32();

        let my_tun = Tunn::new(own_staticsecret_private_key, their_publickey_public_key, None, None, my_index, None).unwrap();
        let their_tun = Tunn::new(their_staticsecret_private_key, own_publickey_public_key, None, None, their_index, None);

        (my_tun, their_tun)
    }

    fn test_send_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let own_handshake_init = tun.produce_handshake_initiation(&mut dst, false);
        assert!(matches!(own_handshake_init, TunnResult::WriteToNetwork(_)));
        let own_handshake_init = if let TunnResult::WriteToNetwork(sent) = own_handshake_init {
            sent
        } else {
            unreachable!();
        };

        own_handshake_init.into()
    }

    fn produce_handshake_response(tun: &mut Tunn, own_handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_resp = tun.decapsulate(None, own_handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        let handshake_resp = if let TunnResult::WriteToNetwork(sent) = handshake_resp {
            sent
        } else {
            unreachable!();
        };

        handshake_resp.into()
    }

    fn consume_handshake_response(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
            sent
        } else {
            unreachable!();
        };

        keepalive.into()
    }

    fn consume_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    fn produce_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = produce_two_tuns();
        let init = test_send_handshake_init(&mut my_tun);
        let resp = produce_handshake_response(&mut their_tun, &init);
        let keepalive = consume_handshake_response(&mut my_tun, &resp);
        consume_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn produce_ipv4_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    #[cfg(feature = "mock-instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let mut dst = vec![0u8; 2048];
        let result = tun.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        let packet_data = if let TunnResult::WriteToNetwork(data) = result {
            data
        } else {
            unreachable!();
        };
        let packet = Tunn::consume_incoming_packet(packet_data).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn produce_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = produce_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = produce_two_tuns();
        let init = test_send_handshake_init(&mut my_tun);
        let packet = Tunn::consume_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = produce_two_tuns();
        let init = test_send_handshake_init(&mut my_tun);
        let resp = produce_handshake_response(&mut their_tun, &init);
        let packet = Tunn::consume_incoming_packet(&resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = produce_two_tuns();
        let init = test_send_handshake_init(&mut my_tun);
        let resp = produce_handshake_response(&mut their_tun, &init);
        let keepalive = consume_handshake_response(&mut my_tun, &resp);
        let packet = Tunn::consume_incoming_packet(&keepalive).unwrap();
        assert!(matches!(packet, Packet::PacketData(_)));
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = produce_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = produce_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let sent_packet_buf = produce_ipv4_udp_packet();
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));

        //Advance to timeout
        mock_instant::MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = produce_two_tuns();

        let init = test_send_handshake_init(&mut my_tun);
        let packet = Tunn::consume_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));

        mock_instant::MockClock::advance(REKEY_TIMEOUT);
        update_timer_results_in_handshake(&mut my_tun)
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = produce_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = produce_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }
}

pub fn verify_hasrodit_getit(
    rodit_id: [u8;RODIT_ID_SZ],
    rodit_id_signature: [u8;RODIT_ID_SIGNATURE_SZ],
) -> Result<(bool,Rodit), WireGuardError> {

let slice_rodtid: &[u8] = &rodit_id[..];
let string_rodtid: &str = std::str::from_utf8(slice_rodtid)
.expect("Error: Failed to convert byte slice to string")
.trim_end_matches('\0');

// Obtain a Peer RODiT from its ID
let account_idargs = "{\"token_id\": \"".to_owned()
    + &string_rodtid+ "\"}";

// CG: Return values need to be honed, probably false / true better than codes here
match nearorg_rpc_token(BLOCKCHAIN_NETWORK, SMART_CONTRACT, "nft_token", &account_idargs) {
    Ok(fetched_rodt) => {
        tracing::info!("Info: Peer RODiT Owner Init Received: {:?}", fetched_rodt.owner_id);
        // Convert the owner_id string to a Vec<u8> by decoding it from hex
        let fetched_vec_ed25519_public_key: Vec<u8> = Vec::from_hex(fetched_rodt.owner_id.clone())
            .expect("Error: Failed to decode hex string");
        // Convert the bytes to a [u8; 32] array
        let fetched_bytes_ed25519_public_key: [u8; RODIT_ID_PK_SZ] = fetched_vec_ed25519_public_key
            .try_into()
            .expect("Error: Invalid byte array length");

        // Parse the signature bytes from packet.rodit_id_signature
        // and assign it to the signature variable
        match Signature::from_bytes(&rodit_id_signature) {
            Ok(signature) => {
                // If the signature parsing is successful, execute this block
                if let Ok(fetched_publickey_ed25519_public_key) = PublicKey::from_bytes(&fetched_bytes_ed25519_public_key) {
                    // If the public key parsing is successful, execute this block
                    if fetched_publickey_ed25519_public_key.verify(
                        string_rodtid.as_bytes(),
                        &signature
                        ).is_ok() {
                        tracing::info!("Info: Peer RODiT possession check confirmed");
                    } else {
                        tracing::trace!("Error: Peer RODiT possession check failed");
                        return Err(WireGuardError::PeerEd25519SignatureVerificationFailure)
                    }
                    // Rest of the code if verification is successful
                } else {
                    // If the public key parsing fails, handle the Error and propagate it
                    tracing::trace!("Error: Peer RODiT possession check failed - Parsing publick key");
                    return Err(WireGuardError::PeerEd25519PublicKeyParsingFailure)
                }
            // Rest of the code if public key parsing is successful
            } Err(_) => {
                // If the signature parsing fails, handle the Error and propagate it
                tracing::trace!("Error: Peer RODiT possession check failed - Obtaining public key");
                return Err(WireGuardError::PeerEd25519SignatureParsingFailure);
            }
        };
        Ok::<(bool,Rodit), WireGuardError>((true,fetched_rodt))
    } Err(err) => {
        // If the nearorg_rpc_token function call returns an Error, execute this block
        tracing::trace!("Error: There is no Peer RODiT associated with the account: {}", err);
        return Err(WireGuardError::PeerEd25519RoditMissing);
    }
}

}

pub fn verify_rodit_isamatch(
    own_serviceproviderid: String,
    peer_serviceprovidersignature: String,
    peer_token_id: [u8;RODIT_ID_SZ],
) -> bool {

let slice_peer_token_id: &[u8] = &peer_token_id[..];
let string_peer_token_id: &str = std::str::from_utf8(slice_peer_token_id)
.expect("Error: Failed to convert byte slice to string")
.trim_end_matches('\0');

// Obtain a Own Service Provider RODiT (Mother RODiT) from its ID
let account_idargs = "{\"token_id\": \"".to_owned()
    + &own_serviceproviderid+ "\"}";
match nearorg_rpc_token(BLOCKCHAIN_NETWORK, SMART_CONTRACT, "nft_token", &account_idargs) {
    Ok(own_serviceprovider_rodt) => {
        // Convert the owner_id string to a Vec<u8> by decoding it from hex
        let own_serviceprovider_vec_ed25519_public_key: Vec<u8> = Vec::from_hex(own_serviceprovider_rodt.owner_id.clone())
        .expect("Error: Failed to decode hex string");

        // Convert the bytes to a [u8; 32] array
        let own_serviceprovider_bytes_ed25519_public_key: [u8; RODIT_ID_PK_SZ] = own_serviceprovider_vec_ed25519_public_key
            .try_into()
            .expect("Error: Invalid byte array length");

        let peer_serviceprovider_bytes_signature = base64decode(&peer_serviceprovidersignature).expect("Error: Failed Base64 decoding");

        let peer_serviceprovider_u864_signature: [u8; RODIT_ID_SIGNATURE_SZ] = peer_serviceprovider_bytes_signature
            .as_slice()
            .try_into()
            .expect("Error: Invalid public key length");

        match Signature::from_bytes(&peer_serviceprovider_u864_signature) {
            Ok(peer_signature) => {
                if let Ok(own_serviceprovider_verifyingkey_ed25519_public_key) = PublicKey::from_bytes(&own_serviceprovider_bytes_ed25519_public_key) {
                    // Verify if the peer_serviceprovidersignature is valid when checked
                    // against the peer_token_id and the public key of the own_serviceproviderid
                    // In other words, if they have been signed with the same private key
                    if own_serviceprovider_verifyingkey_ed25519_public_key.verify(
                        string_peer_token_id.as_bytes(),
                        &peer_signature
                        ).is_ok() {
                            tracing::info!("Info Peer RODiT matches Own RODiT");
                            return true;
                        } else {
                            tracing::error!("Error: Peer RODiT does not match Own RODiT");
                            return false;
                        }
                    } else {
                        tracing::error!("Error: Peer RODiT does not match Own RODiT - Parsing public key");
                        return false;
                    }
            } Err(_) => {
                tracing::error!("Error: Peer RODiT does not match Own RODiT - Obtaining public key");
                return false;
            }
        };
        } Err(_) => {
            tracing::error!("Error: Peer RODiT does not match Own RODiT - Fetching");
            return false;
        }
}
}

pub fn verify_rodit_islive(
    peer_rodit_notafter: String,
    peer_rodit_notbefore: String,
) -> bool {

// 1970-01-01 chosen as nul date considering Unix and X.509 standards for timekeeping
let naivedatetime_nul = NaiveDateTime::parse_from_str("1970-01-01", "%Y-%m-%d")
    .unwrap_or_default(); // Use a default value if parsing fails
// naivedatetime_nul value is 1970-01-01 00:00:00
let naivedate_notafter = NaiveDate::parse_from_str(&peer_rodit_notafter, "%Y-%m-%d")
    .unwrap_or_default(); // Use a default value if parsing fails
let naivedate_notbefore = NaiveDate::parse_from_str(&peer_rodit_notbefore, "%Y-%m-%d")
    .unwrap_or_default(); // Use a default value if parsing fails
let niltime = NaiveTime::from_hms_milli_opt(0, 0, 0, 0).unwrap();
let naivedatetime_notafter = NaiveDateTime::new(naivedate_notafter, niltime);
let naivedatetime_notbefore = NaiveDateTime::new(naivedate_notbefore, niltime);

let string_timenow = nearorg_rpc_timestamp(BLOCKCHAIN_NETWORK);

// Convert the timestamp string into an i64
// Try to parse the timestamp, and if successful, create a NaiveDateTime from it
if let Ok(string_timenow) = string_timenow {
    if let Ok(i64_timestamp) = string_timenow.parse::<i64>() {
        let naivedatetime_timestamp = NaiveDateTime::from_timestamp_opt(i64_timestamp / 1000000000, 0);

        if ((naivedatetime_timestamp <= Some(naivedatetime_notafter)) || (naivedatetime_notafter == naivedatetime_nul))
            && ((naivedatetime_timestamp >= Some(naivedatetime_notbefore)) || (naivedatetime_notbefore == naivedatetime_nul)) {
            tracing::info!("Info Peer RODiT is live");
            return true;
        } else {
            tracing::error!("Error: Peer RODiT is not live - notbefore {:?} now {:?} notafter {:?}",
                naivedatetime_notbefore,
                naivedatetime_timestamp,
                naivedatetime_notafter);
            return false;
        }
    } else {
        tracing::error!("Error: Can't parse near block timestamp");
        return false;
    }
} else {
    // Handle the case where string_timenow is an error
    tracing::error!("Error: {}", string_timenow.unwrap_err());
    return false;
}


}

pub fn verify_rodit_isactive(
    token_id: String,
    own_subjectuniqueidentifierurl: String,
) -> bool {

let dnssecresolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

let domainandextension = Regex::new(r"(\w+\.\w+)$").unwrap();

// Find the rightmost part (domain and extension)
if let Some(maindomain) = domainandextension.captures(&own_subjectuniqueidentifierurl) {
    let domainandextension = &maindomain[1];
    let revokingdnsentry = token_id.clone() + ".revoked." + &domainandextension;
    let cfgresponse = dnssecresolver.txt_lookup(revokingdnsentry.clone());
    if cfgresponse.iter().next().is_some() {
        tracing::error!("Error: Peer RODiT {} revoked by {} as per {}", token_id, domainandextension, revokingdnsentry);
        return false
    } else {
        // If an Error is found, instead of an entry, the Peer RODiT is not revoked
        tracing::info!("Info Peer RODiT is not revoked");
        return true
    };
} else {
    // If an Error is found, instead of an entry, the Peer RODiT is not revoked
    tracing::info!("Info Peer RODiT is not revoked");
    return true
}

}

pub fn verify_rodit_smartcontract_istrusted(
    own_subjectuniqueidentifierurl: String,
) -> bool {

let dnssecresolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

let smart_contract = SMART_CONTRACT;
let smart_contract_nonear = smart_contract.replace(".testnet", "");
let smart_contract_url = smart_contract_nonear.replace("-", ".");

let domainandextension = Regex::new(r"(\w+\.\w+)$").unwrap();

// Find the rightmost part (domain and extension)
if let Some(maindomain) = domainandextension.captures(&own_subjectuniqueidentifierurl) {
    let domainandextension = &maindomain[1];
    let enablingdnsentry = smart_contract_nonear + ".smartcontract." + &domainandextension;
    let cfgresponse = dnssecresolver.txt_lookup(enablingdnsentry.clone());
    if cfgresponse.iter().next().is_some() {
        tracing::trace!("Info Smart Contract is trusted");
        return true
    } else {
        tracing::error!("Error: Smart Contract {} not trusted by {} in verify_smartcontract_istruste", smart_contract_url, domainandextension);
        return false
    };
} else {
    tracing::error!("Error: Domain {} can't be parsed in verify_rodit_smartcontract_istrusted", domainandextension);
    return false
}

}

pub fn nearorg_rpc_timestamp(
    xnet: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client: Client = Client::new();
    let url: String = "https://rpc".to_string() + &xnet + "near.org";
    let json_data: String = format!(
        r#"{{
            "jsonrpc": "2.0",
            "id": "dontcare",
            "method": "block",
            "params": {{
                "finality": "final"
            }}
        }}"#
    );
    let response: reqwest::blocking::Response = client
        .post(&url)
        .body(json_data)
        .header("Content-Type", "application/json")
        .send()?;
    let response_text: String = response.text()?;
    let parsed_json: Value = serde_json::from_str(&response_text).unwrap();
    if let Some(timestamp) = parsed_json["result"]["header"]["timestamp"].as_i64() {
        Ok(timestamp.to_string())
    } else {
        Ok("0".to_string())
    }
}

pub fn nearorg_rpc_token(
    xnet: &str,
    id: &str,
    method_name: &str,
    args: &str,
) -> Result<Rodit, Box<dyn std::error::Error>> {
    let client: Client = Client::new();
    let url: String = "https://rpc".to_string() + &xnet + "near.org";
    if xnet == "." {
        tracing::debug!("Info: Blockchain Directory Network is mainnet (nearorg_rpc_token)");
    } else {
        tracing::debug!("Info: Blockchain Directory Network is {} nearorg_rpc_token",xnet);
    }
    let json_data: String = format!(
        r#"{{
            "jsonrpc": "2.0",
            "id": "{}",
            "method": "query",
            "params": {{
                "request_type": "call_function",
                "finality": "final",
                "account_id": "{}",
                "method_name": "{}",
                "args_base64": "{}"
            }}
        }}"#,
        id, id, method_name, base64::encode_config(args,URL_SAFE_NO_PAD)
    );
    let response: reqwest::blocking::Response = client
        .post(&url)
        .body(json_data)
        .header("Content-Type", "application/json")
        .send()?;

    let response_text: String = response.text()?;

    let parsed_json: Value = serde_json::from_str(&response_text).unwrap();

    let result_array = parsed_json["result"]["result"].as_array().ok_or("Error: Result is not an array")?;

    let result_bytes: Vec<u8> = result_array
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    let result_slice: &[u8] = &result_bytes;

    let result_string = String::from_utf8(result_slice.to_vec()).unwrap();

    let rodt: Rodit = serde_json::from_str(&result_string).unwrap();

    Ok(rodt.clone())
}
