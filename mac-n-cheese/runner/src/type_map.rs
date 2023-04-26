use std::any::Any;

use smallvec::SmallVec;

#[derive(Default)]
pub struct SmallTypeMap<const INLINE: usize> {
    contents: SmallVec<[Box<dyn Any + Send + Sync>; INLINE]>,
}

#[allow(unused)]
impl<const INLINE: usize> SmallTypeMap<INLINE> {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn get<T: 'static + Send + Sync>(&self) -> Option<&T> {
        self.contents.iter().find_map(|x| x.downcast_ref())
    }
    pub fn get_mut<T: 'static + Send + Sync>(&mut self) -> Option<&mut T> {
        self.contents.iter_mut().find_map(|x| x.downcast_mut())
    }
    pub fn insert<T: 'static + Send + Sync>(&mut self, t: T) -> Option<T> {
        for x in self.contents.iter_mut() {
            if let Some(x) = x.downcast_mut() {
                return Some(std::mem::replace(x, t));
            }
        }
        self.contents.push(Box::new(t));
        None
    }
    pub fn len(&self) -> usize {
        self.contents.len()
    }
}
