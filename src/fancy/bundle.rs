/// A collection of wires, useful for the garbled gadgets defined by `BundleGadgets`.
#[derive(Clone)]
pub struct Bundle<W: Clone + HasModulus>(Vec<W>);

impl<W: Clone + HasModulus> Bundle<W> {
    /// Create a new bundle from some wires.
    pub fn new(ws: Vec<W>) -> Bundle<W> {
        Bundle(ws)
    }

    /// Return the moduli of all the wires in the bundle.
    pub fn moduli(&self) -> Vec<u16> {
        self.0.iter().map(HasModulus::modulus).collect()
    }

    /// Extract the wires from this bundle.
    pub fn wires(&self) -> &[W] {
        &self.0
    }

    /// Get the number of wires in this bundle.
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Whether this bundle only contains residues in mod 2.
    pub fn is_binary(&self) -> bool {
        self.moduli().iter().all(|m| *m == 2)
    }

    /// Returns a new bundle only containing wires with matching moduli.
    pub fn with_moduli(&self, moduli: &[u16]) -> Bundle<W> {
        let old_ws = self.wires();
        let mut new_ws = Vec::with_capacity(moduli.len());
        for &p in moduli {
            if let Some(w) = old_ws.iter().find(|&x| x.modulus() == p) {
                new_ws.push(w.clone());
            } else {
                panic!("Bundle::with_moduli: no {} modulus in bundle", p);
            }
        }
        Bundle(new_ws)
    }

    /// Pad the Bundle with val, n times.
    pub fn pad(&mut self, val: W) {
        self.0.push(val);
    }

    /// Extract a wire from the Bundle, removing it and returning it.
    pub fn extract(&mut self, wire_index: usize) -> W {
        self.0.remove(wire_index)
    }

    /// Access the underlying iterator
    pub fn iter(&self) -> std::slice::Iter<W> {
        self.0.iter()
    }
}

impl <W: Clone + HasModulus> Index<usize> for Bundle<W> {
    type Output = W;

    fn index(&self, idx: usize) -> &Self::Output {
        self.0.index(idx)
    }
}
