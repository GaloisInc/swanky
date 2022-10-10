//! Fancy object to compute the multiplicative depth of a computation.

use crate::{
    errors::FancyError,
    fancy::{Fancy, FancyInput, FancyReveal, HasModulus},
    FancyArithmetic, FancyBinary,
};
use std::cmp::max;

/// Carries the depth of the computation.
#[derive(Clone, Debug)]
pub struct DepthItem {
    modulus: u16,
    depth: usize,
}

impl HasModulus for DepthItem {
    fn modulus(&self) -> u16 {
        self.modulus
    }
}

/// Errors thrown by the Fancy computation.
#[derive(Debug)]
pub enum DepthError {
    /// Projection is unsupported by the depth informer
    ProjUnsupported,
    /// Error from Fancy library.
    Underlying(FancyError),
}

impl From<FancyError> for DepthError {
    fn from(e: FancyError) -> Self {
        DepthError::Underlying(e)
    }
}

impl std::fmt::Display for DepthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::ProjUnsupported => writeln!(f, "Projection unsupported"),
            Self::Underlying(e) => writeln!(f, "Fancy error: {}", e),
        }
    }
}

/// Fancy Object which computes information about the circuit of interest to FHE.
#[derive(Clone, Debug)]
pub struct DepthInformer {
    ninputs: usize,
    nconstants: usize,
    nadds: usize,
    nsubs: usize,
    ncmuls: usize,
    nmuls: usize,
    mul_depth: usize,
}

impl std::fmt::Display for DepthInformer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "computation info:")?;
        writeln!(f, "  inputs:             {:16}", self.ninputs)?;
        writeln!(f, "  constants:          {:16}", self.nconstants)?;
        writeln!(f, "  additions:          {:16}", self.nadds)?;
        writeln!(f, "  subtractions:       {:16}", self.nsubs)?;
        writeln!(f, "  cmuls:              {:16}", self.ncmuls)?;
        writeln!(f, "  muls:               {:16}", self.nmuls)?;
        writeln!(
            f,
            "  total gates:        {:16}",
            self.nadds + self.nsubs + self.ncmuls + self.nmuls
        )?;
        writeln!(f, "  mul depth:          {:16}", self.mul_depth)?;
        Ok(())
    }
}

impl DepthInformer {
    /// Create a new DepthInformer
    pub fn new() -> DepthInformer {
        DepthInformer {
            ninputs: 0,
            nconstants: 0,
            nadds: 0,
            nsubs: 0,
            ncmuls: 0,
            nmuls: 0,
            mul_depth: 0,
        }
    }
}

impl FancyInput for DepthInformer {
    type Item = DepthItem;
    type Error = DepthError;

    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Self::Item>, Self::Error> {
        self.ninputs += moduli.len();
        Ok(moduli
            .iter()
            .map(|q| DepthItem {
                modulus: *q,
                depth: 0,
            })
            .collect())
    }

    fn encode_many(
        &mut self,
        _values: &[u16],
        moduli: &[u16],
    ) -> Result<Vec<Self::Item>, Self::Error> {
        self.receive_many(moduli)
    }
}

impl FancyBinary for DepthInformer {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        FancyArithmetic::add(self, x, y)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        FancyArithmetic::mul(self, x, y)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nadds += 1;
        Ok(DepthItem {
            modulus: x.modulus,
            depth: x.depth,
        })
    }
}

impl FancyArithmetic for DepthInformer {
    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nadds += 1;
        Ok(DepthItem {
            modulus: x.modulus,
            depth: max(x.depth, y.depth),
        })
    }

    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nsubs += 1;
        Ok(DepthItem {
            modulus: x.modulus,
            depth: max(x.depth, y.depth),
        })
    }

    fn cmul(&mut self, x: &Self::Item, _y: u16) -> Result<Self::Item, Self::Error> {
        self.ncmuls += 1;
        Ok(DepthItem {
            modulus: x.modulus,
            depth: x.depth + 1,
        })
    }

    fn mul(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nmuls += 1;
        Ok(DepthItem {
            modulus: x.modulus,
            depth: max(x.depth, y.depth) + 1,
        })
    }

    fn proj(
        &mut self,
        _x: &Self::Item,
        _q: u16,
        _tt: Option<Vec<u16>>,
    ) -> Result<Self::Item, Self::Error> {
        Err(DepthError::ProjUnsupported)
    }
}

impl Fancy for DepthInformer {
    type Item = DepthItem;
    type Error = DepthError;

    fn constant(&mut self, _val: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.nconstants += 1;
        Ok(DepthItem {
            modulus: q,
            depth: 0,
        })
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error> {
        self.mul_depth = max(self.mul_depth, x.depth);
        Ok(None)
    }
}

impl FancyReveal for DepthInformer {
    fn reveal(&mut self, _x: &Self::Item) -> Result<u16, Self::Error> {
        Ok(0)
    }
}
