pub trait FbVectorExt {
    type Output;
    fn get_opt(&self, idx: usize) -> Option<Self::Output>;
}
impl<'a, T: flatbuffers::Follow<'a>> FbVectorExt for flatbuffers::Vector<'a, T> {
    type Output = T::Inner;
    fn get_opt(&self, idx: usize) -> Option<T::Inner> {
        if idx < self.len() {
            Some(self.get(idx))
        } else {
            None
        }
    }
}
