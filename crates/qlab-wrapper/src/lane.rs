//! A foreign AIR evaluated at a column offset: [`LaneBuilder`] hands the
//! Keccak-f AIR (`p3-keccak-air`) the wrapper's lane columns. Moved from
//! qlab-bench's `m4skel` (lab #785, F5-1), unchanged.
use p3_air::{AirBuilder, WindowAccess};

#[derive(Clone)]
pub struct LaneWindow<W> {
    inner: W,
    off: usize,
    width: usize,
}

pub struct LaneBuilder<'a, AB: AirBuilder> {
    pub inner: &'a mut AB,
    pub off: usize,
    pub width: usize,
}

impl<'a, AB: AirBuilder> AirBuilder for LaneBuilder<'a, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = LaneWindow<AB::MainWindow>;

    fn main(&self) -> Self::MainWindow {
        LaneWindow {
            inner: self.inner.main(),
            off: self.off,
            width: self.width,
        }
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x);
    }
}

impl<T, W: WindowAccess<T>> WindowAccess<T> for LaneWindow<W> {
    fn current_slice(&self) -> &[T] {
        &self.inner.current_slice()[self.off..self.off + self.width]
    }
    fn next_slice(&self) -> &[T] {
        &self.inner.next_slice()[self.off..self.off + self.width]
    }
}
