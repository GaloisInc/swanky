// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#[cfg(feature = "unstable")]
pub mod psty;
pub mod psz;

pub type PsiSender = psz::Sender;
pub type PsiReceiver = psz::Receiver;
#[cfg(feature = "unstable")]
pub type ExtendPsiSender = psty::Sender;
#[cfg(feature = "unstable")]
pub type ExtendPsiReceiver = psty::Receiver;
