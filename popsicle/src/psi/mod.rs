// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#[cfg(feature = "unstable")]
pub mod kmprt;
#[cfg(feature = "unstable")]
pub mod psty;
pub mod psz;

/// Private set intersection sender.
pub type Sender = psz::Sender;
/// Private set intersection receiver.
pub type Receiver = psz::Receiver;

#[cfg(feature = "unstable")]
/// Extended private set intersection sender.
pub type ExtendedSender = psty::Sender;
#[cfg(feature = "unstable")]
/// Extended private set intersection receiver.
pub type ExtendedReceiver = psty::Receiver;

#[cfg(feature = "unstable")]
/// Multi-party private set intersection sender.
pub type MultiPartySender = kmprt::Sender;
#[cfg(feature = "unstable")]
/// Multi-party private set intersection receiver.
pub type MultiPartyReceiver = kmprt::Receiver;
