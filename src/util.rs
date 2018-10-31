pub trait IterToVec<T> {
    fn to_vec(self) -> Vec<T>;
}

impl <T,I> IterToVec<T> for I where
    I: Iterator<Item=T>
{
    fn to_vec(self) -> Vec<T> {
        self.collect()
    }
}
