//! `fancy-garbling` provides boolean and arithmetic garbling capabilities.
#![allow(clippy::all)]
#![allow(non_snake_case)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

pub mod circuit;
pub mod classic;
pub mod depth_informer;
pub mod dummy;
pub mod errors;
mod fancy;
mod garble;
pub mod informer;
mod parser;
pub mod twopac;
pub mod util;
mod wire;

pub use crate::{errors::FancyError, fancy::*, garble::*, wire::*};
