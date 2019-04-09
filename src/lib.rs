// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2018 Brent Carmer.
// See LICENSE for licensing information.

//! `fancy-garbling` provides boolean and arithmetic garbling capabilities.

#![deny(clippy::all)]
#![allow(
    clippy::cast_lossless,
    clippy::new_without_default,
    clippy::type_complexity,
    clippy::many_single_char_names,
    clippy::needless_range_loop
)]
#![allow(non_snake_case)]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(stdsimd))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]

pub mod circuit;
pub mod dummy;
pub mod error;
mod fancy;
mod garble;
pub mod informer;
mod parser;
pub mod r#static;
pub mod util;
mod wire;

pub use crate::error::FancyError;
pub use crate::fancy::*;
pub use crate::garble::*;
pub use crate::r#static::*;
pub use crate::wire::*;
