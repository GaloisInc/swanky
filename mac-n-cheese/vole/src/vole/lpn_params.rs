#[derive(Clone, Copy)]
pub(crate) struct LpnParams {
    /// Hamming weight $`t`$ of the error vector $`e`$ used in the LPN assumption.
    pub(crate) weight: usize,
    /// $`\log_2\left(\frac{n}{t}\right)`$ where $`t`$ is `self.weight` and $`n`$ is the number
    /// of columns.
    pub(crate) log2m: usize,
    /// Number of rows $`k`$ in the LPN matrix.
    pub(crate) rows: usize,
}
impl LpnParams {
    /// `cols / weight`
    pub(crate) const fn m(&self) -> usize {
        1 << self.log2m
    }
    /// The number of columns, $`n`$, in the LPN matrix.
    pub(crate) const fn cols(&self) -> usize {
        self.m() * self.weight
    }
    /// How many VOLEs are needed to extend
    pub(crate) const fn voles_needed_for_extend(&self, field_extension_size: usize) -> usize {
        self.rows + self.weight + field_extension_size
    }

    pub(crate) const fn total_output_voles(&self) -> usize {
        self.cols()
    }

    #[cfg(test)]
    fn bits_of_security(&self) -> f64 {
        let k = self.rows as f64;
        let n = self.cols() as f64;
        let t = i32::try_from(self.weight).unwrap();
        ((k + 1.0) / (1.0 - (k / n)).powi(t)).log2()
    }
}
#[cfg(test)]
impl std::fmt::Debug for LpnParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sizes = crate::vole::sizes::VoleSizes::from_lpn_params::<
            scuttlebutt::field::F2,
            scuttlebutt::field::F63b,
        >(*self);
        let total_comms =
            sizes.comms_1s + sizes.comms_2r + sizes.comms_3s + sizes.comms_4r + sizes.comms_5s;
        f.debug_struct("LpnParams")
            .field("weight", &self.weight)
            .field("log2m", &self.log2m)
            .field("rows", &self.rows)
            .field("total_output_voles", &self.total_output_voles())
            .field("total_comms", &total_comms)
            .field(
                "bits_per_vole",
                &(((total_comms * 8) as f64) / (self.total_output_voles() as f64)),
            )
            .finish()
    }
}

pub(super) const LPN_EXTEND_PARAMS_WEIGHT: usize = 279;
pub(super) const LPN_EXTEND_PARAMS_LOG_M: usize = 10;
pub(crate) const fn extend_params(field_extension_size: usize) -> LpnParams {
    let target_voles_needed_for_extend = 1 << 16;
    let weight = LPN_EXTEND_PARAMS_WEIGHT;
    let rows = target_voles_needed_for_extend - field_extension_size - weight;
    LpnParams {
        weight,
        rows,
        log2m: LPN_EXTEND_PARAMS_LOG_M,
    }
}

/*#[test]
fn blarg_test() {
    let mut out = Vec::new();
    for weight in 1..2048 {
        let field_extension_size = 63;
        let target_voles_needed_for_extend = 1 << 16;
        let rows = target_voles_needed_for_extend - field_extension_size - weight;
        let params = LpnParams {
            weight,
            rows,
            log2m: LPN_EXTEND_PARAMS_LOG_M,
        };
        assert_eq!(
            params.voles_needed_for_extend(field_extension_size),
            target_voles_needed_for_extend,
        );
        if params.bits_of_security() < 124.0 {
            continue;
        }
        out.push(params);
    }
    dbg!(out.len());
    out.sort_unstable_by_key(|x| x.total_output_voles());
    dbg!(out.first());
    dbg!(out.last());
    panic!();
}*/

#[test]
fn assert_extend_params_meets_criteria() {
    for field_extension_size in [1, 40, 45, 56, 63, 128] {
        let extend_params = extend_params(field_extension_size);
        assert_eq!(
            extend_params.voles_needed_for_extend(field_extension_size),
            1 << 16
        );
        assert!(extend_params.bits_of_security() >= 120.0);
        // Assert that fork will be able to produce enough VOLES to do the extension.
        assert!(
            extend_params.total_output_voles()
                >= 2 * extend_params.voles_needed_for_extend(field_extension_size)
        );
        assert!(
            extend_params.voles_needed_for_extend(field_extension_size)
                <= extend_params.voles_needed_for_extend(field_extension_size)
        );
    }
}
