// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

pub mod kmprt;

#[cfg(feature = "psty_payload")]
pub mod psty_payload;
#[cfg(feature = "psty")]
pub mod psty;
pub mod psz;

/// Private set intersection sender.
pub type Sender = psz::Sender;
/// Private set intersection receiver.
pub type Receiver = psz::Receiver;

#[cfg(feature = "psty")]
/// Extended private psty intersection sender.
pub type ExtendedSender = psty::Sender;
#[cfg(feature = "psty")]
/// Extended private set intersection receiver.
pub type ExtendedReceiver = psty::Receiver;


#[cfg(feature = "psty_payload")]
/// Private set intersection with associated payloads sender.
pub type SenderPayload = psty_payload::Sender;
#[cfg(feature = "psty_payload")]
/// Private set intersection with associated payloads receiver.
pub type ReceiverPayload  = psty_payload::Receiver;


/// Multi-party private set intersection sender.
pub type MultiPartySender = kmprt::Sender;
/// Multi-party private set intersection receiver.
pub type MultiPartyReceiver = kmprt::Receiver;
