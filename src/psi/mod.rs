// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

pub mod psz;

#[cfg(feature = "unstable")]
pub mod psty;

#[cfg(feature = "unstable")]
pub mod kmprt;

/// Private set intersection sender.
pub type PsiSender = psz::Sender;

/// Private set intersection receiver.
pub type PsiReceiver = psz::Receiver;

#[cfg(feature = "unstable")]
/// Extended private set intersection sender.
pub type ExtendPsiSender = psty::Sender;

#[cfg(feature = "unstable")]
/// Extended private set intersection receiver.
pub type ExtendPsiReceiver = psty::Receiver;
