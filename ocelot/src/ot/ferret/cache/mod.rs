mod receiver;
mod sender;

use std::ops::Deref;

pub use receiver::CachedReceiver;
pub use sender::CachedSender;

pub struct VecTake<'a, T> {
    len: usize,
    vec: &'a mut Vec<T>,
}

impl<'a, T> VecTake<'a, T> {
    fn new(vec: &'a mut Vec<T>, len: usize) -> VecTake<'a, T> {
        VecTake { len, vec }
    }
}

impl<'a, T> Deref for VecTake<'a, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.vec[self.vec.len() - self.len..]
    }
}

impl<'a, T> Drop for VecTake<'a, T> {
    fn drop(&mut self) {
        debug_assert!(self.len <= self.vec.len());
        self.vec.truncate(self.vec.len() - self.len);
    }
}

impl<'a, T> AsRef<[T]> for VecTake<'a, T> {
    fn as_ref(&self) -> &[T] {
        &self.vec[self.vec.len() - self.len..]
    }
}
