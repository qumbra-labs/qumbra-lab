//! The one native-statement test that needs the bench's W fixtures
//! (`neg::wfixture`), kept here when `f4::native` moved to qlab-wprover
//! (lab #847 S1a). Verbatim but for the fixture's path.
use crate::f3::native::append;
use super::native::*;

/// Review T1: the native refusals of the subtree absorb's alignment and
/// of a short P member — each from both paths, the state untouched, no
/// panic.
#[test]
fn f4_native_align_and_short_p_refusals() {
    use super::neg::{wfixture, SEED};
    let fx = wfixture(&[WTag::S], SEED);
    let mut rin = fx.rin;
    rin.aa_next += 1;
    assert_eq!(check_wrapper_leaf(&rin, &fx.inp, &fx.members, &fx.wit).unwrap_err(), WError::AbsAlign);
    let mut st = fx.pre.clone();
    append(&mut st.aa, &[9; 4]);
    let before = st.roots();
    assert_eq!(st.apply(&fx.inp, &fx.members).unwrap_err(), WError::AbsAlign);
    assert_eq!(st.roots(), before, "a refused wrapper leaves the state as it was");

    let fx = wfixture(&[WTag::P], SEED);
    let mut short = fx.members.clone();
    short[0].pvs.pop();
    assert_eq!(check_wrapper_leaf(&fx.rin, &fx.inp, &short, &fx.wit).unwrap_err(), WError::Surface);
    let mut st = fx.pre.clone();
    assert_eq!(st.apply(&fx.inp, &short).unwrap_err(), WError::Surface);
}
