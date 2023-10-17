use eyre::Result;

use crate::backend_trait::BackendT;

fn eval_zero_poly<B: BackendT>(
    backend: &mut B,
    mx: B::FieldElement, // - x
    zs: &[B::Wire],
) -> Result<B::Wire> {
    let mut terms = zs.iter();

    let z0 = terms.next().unwrap();
    let mut rs = backend.add_constant(z0, mx)?;

    for zi in terms {
        let df = backend.add_constant(zi, mx)?;
        rs = backend.mul(&rs, &df)?;
    }

    Ok(rs)
}

pub(super) fn permutation<B: BackendT>(
    backend: &mut B,
    x: B::FieldElement,
    lhs: &[B::Wire],
    rhs: &[B::Wire],
) -> Result<()> {
    debug_assert_eq!(lhs.len(), rhs.len());
    if lhs.len() == 0 {
        return Ok(());
    }
    let mx = -x;
    let yl = eval_zero_poly(backend, mx, lhs)?;
    let yr = eval_zero_poly(backend, mx, rhs)?;
    let zero = backend.sub(&yl, &yr)?;
    backend.assert_zero(&zero)
}
