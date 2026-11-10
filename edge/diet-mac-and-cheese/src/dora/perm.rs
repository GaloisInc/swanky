use swanky_channel::Channel;
use swanky_error::Result;

use crate::backend_trait::BackendT;

fn eval_zero_poly<B: BackendT>(
    backend: &mut B,
    mx: B::FieldElement, // - x
    zs: &[B::Wire],
    channel: &mut Channel,
) -> Result<B::Wire> {
    let mut terms = zs.iter();

    let z0 = terms.next().unwrap();
    let mut rs = backend.add_constant(z0, mx)?;

    for zi in terms {
        let df = backend.add_constant(zi, mx)?;
        rs = backend.mul(&rs, &df, channel)?;
    }

    Ok(rs)
}

pub fn permutation<B: BackendT>(
    backend: &mut B,
    x: B::FieldElement,
    lhs: &[B::Wire],
    rhs: &[B::Wire],
    channel: &mut Channel,
) -> Result<()> {
    debug_assert_eq!(lhs.len(), rhs.len());
    if lhs.is_empty() {
        return Ok(());
    }
    let mx = -x;
    let yl = eval_zero_poly(backend, mx, lhs, channel)?;
    let yr = eval_zero_poly(backend, mx, rhs, channel)?;
    let zero = backend.sub(&yl, &yr)?;
    backend.assert_zero(&zero, channel)
}
