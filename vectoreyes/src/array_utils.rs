//! Perform manually unrolled operations on arrays.
//!
//! Look at [ArrayUnrolledExt] for the meat of this module.

/// A type which can be used to require that unrolled operations exist for a given array size.
///
/// # Example
/// ```
/// use vectoreyes::array_utils::*;
/// pub fn make_fun_array<const N: usize>() -> [usize; N]
///     where ArrayUnrolledOps: UnrollableArraySize<N>
/// {
///     <[usize; N]>::array_generate(|i| i + 10)
/// }
/// assert_eq!(make_fun_array::<4>(), [10, 11, 12, 13]);
/// ```
pub enum ArrayUnrolledOps {}

/// A marker trait you probably won't need to use directly. See the module documentation for
/// more info.
pub trait UnrollableArraySize<const N: usize> {
    fn array_generate<T, F: FnMut(usize) -> T>(f: F) -> [T; N];
    fn array_map<T, U, F: FnMut(T) -> U>(arr: [T; N], f: F) -> [U; N];
    fn array_map_result<T, U, E, F: FnMut(T) -> Result<U, E>>(
        arr: [T; N],
        f: F,
    ) -> Result<[U; N], E>;
    fn array_fold<T, U, F: FnMut(U, T) -> U>(arr: [T; N], init: U, f: F) -> U;
    fn array_zip<T1, T2>(arr1: [T1; N], arr2: [T2; N]) -> [(T1, T2); N];
    fn array_enumerate<T>(arr: [T; N]) -> [(usize, T); N];
    fn array_as_ref<T>(arr: &[T; N]) -> [&T; N];
    fn array_as_mut<T>(arr: &mut [T; N]) -> [&mut T; N];
}

/// Manually unrolled operations on arrays.
///
/// To ensure that operations are unrolled, consider annotating your closures with
/// `#[inline(always)]`. See the examples below for more details.
pub trait ArrayUnrolledExt<T, const N: usize>: Sized {
    /// Perform some computation over the elements of an array.
    #[inline(always)]
    fn array_for_each<F: FnMut(T)>(self, f: F) {
        let _ = self.array_map(f);
    }
    /// Generate an array by filling the entries.
    /// # Example
    /// ```
    /// use vectoreyes::array_utils::*;
    /// let arr = <[usize; 2]>::array_generate(#[inline(always)] |i| i + 1);
    /// assert_eq!(arr, [1, 2]);
    /// ```
    fn array_generate<F: FnMut(usize) -> T>(f: F) -> [T; N];
    /// Map over elements of an array.
    /// # Example
    /// ```
    /// use vectoreyes::array_utils::*;
    /// let arr = [0, 1];
    /// assert_eq!(arr.array_map(#[inline(always)] |x| x + 1), [1, 2]);
    /// ```
    fn array_map<U, F: FnMut(T) -> U>(self, f: F) -> [U; N];
    /// Map over elements of an array, halting on the first error.
    /// # Example
    /// ```
    /// use vectoreyes::array_utils::*;
    /// let arr = [0, 1];
    /// assert_eq!(arr.array_map_result::<u32, u32, _>(#[inline(always)] |x| Err(x)), Err(0));
    /// assert_eq!(arr.array_map_result::<u32, u32, _>(#[inline(always)] |x| Ok(x)), Ok([0, 1]));
    /// ```
    fn array_map_result<U, E, F: FnMut(T) -> Result<U, E>>(self, f: F) -> Result<[U; N], E>;
    /// Fold over an array.
    /// # Example
    /// ```
    /// use vectoreyes::array_utils::*;
    /// let out = [1, 2, 3].array_fold(0, #[inline(always)] |acu, x| acu + x);
    /// assert_eq!(out, 6);
    /// ```
    fn array_fold<U, F: FnMut(U, T) -> U>(self, init: U, f: F) -> U;
    /// Zip two arrays together.
    /// # Example
    /// ```
    /// use vectoreyes::array_utils::*;
    /// assert_eq!(
    ///     ['a', 'b', 'c'].array_zip(['x', 'y', 'z']),
    ///     [('a', 'x'), ('b', 'y'), ('c', 'z')]
    /// );
    /// ```
    fn array_zip<T2>(self, arr2: [T2; N]) -> [(T, T2); N];
    /// Produce an array where each element is a tuple containing each element's index.
    /// # Example
    /// ```
    /// use vectoreyes::array_utils::*;
    /// assert_eq!(
    ///     ['a', 'b', 'c'].array_enumerate(),
    ///     [(0, 'a'), (1, 'b'), (2, 'c')],
    /// );
    /// ```
    fn array_enumerate(self) -> [(usize, T); N];
    /// Produce an array containing references to the initial array.
    fn array_as_ref(&self) -> [&T; N];
    /// Produce an array containing mutable references to the initial array.
    fn array_as_mut(&mut self) -> [&mut T; N];
}
impl<T, const N: usize> ArrayUnrolledExt<T, N> for [T; N]
where
    ArrayUnrolledOps: UnrollableArraySize<N>,
{
    #[inline(always)]
    fn array_generate<F: FnMut(usize) -> T>(f: F) -> [T; N] {
        ArrayUnrolledOps::array_generate(f)
    }
    #[inline(always)]
    fn array_map<U, F: FnMut(T) -> U>(self, f: F) -> [U; N] {
        ArrayUnrolledOps::array_map(self, f)
    }
    #[inline(always)]
    fn array_map_result<U, E, F: FnMut(T) -> Result<U, E>>(self, f: F) -> Result<[U; N], E> {
        ArrayUnrolledOps::array_map_result(self, f)
    }
    #[inline(always)]
    fn array_fold<U, F: FnMut(U, T) -> U>(self, init: U, f: F) -> U {
        ArrayUnrolledOps::array_fold(self, init, f)
    }
    #[inline(always)]
    fn array_zip<T2>(self, arr2: [T2; N]) -> [(T, T2); N] {
        ArrayUnrolledOps::array_zip(self, arr2)
    }
    #[inline(always)]
    fn array_enumerate(self) -> [(usize, T); N] {
        ArrayUnrolledOps::array_enumerate(self)
    }
    #[inline(always)]
    fn array_as_ref(&self) -> [&T; N] {
        ArrayUnrolledOps::array_as_ref(self)
    }
    #[inline(always)]
    fn array_as_mut(&mut self) -> [&mut T; N] {
        ArrayUnrolledOps::array_as_mut(self)
    }
}

pub trait ArrayAdjacentPairs {
    type T;
    /// An array which is `[Self::T; ceil(Self::LEN / 2)]`
    type AdjacentPairs;

    /// Turn an array into an array of pairs where each element is paired with an adjacent element.
    /// If the array has odd length, use the fallback.
    /// # Example
    /// ```
    /// use vectoreyes::array_utils::*;
    /// assert_eq!(
    ///     [0, 1, 2, 3].pair_adjacent_maybe_odd(42),
    ///     [(0, 1), (2, 3)]
    /// );
    /// assert_eq!(
    ///     [0, 1, 2, 3, 4].pair_adjacent_maybe_odd(42),
    ///     [(0, 1), (2, 3), (4, 42)]
    /// );
    /// ```
    fn pair_adjacent_maybe_odd(self, fallback: Self::T) -> Self::AdjacentPairs;
}

/// An even-sized array.
pub trait EvenArrayAdjacentPairs: ArrayAdjacentPairs {
    /// Turn an array into an array of pairs where each element is paired with an adjacent element.
    /// # Example
    /// ```
    /// use vectoreyes::array_utils::*;
    /// assert_eq!(
    ///     [0, 1, 2, 3].pair_adjacent(),
    ///     [(0, 1), (2, 3)]
    /// );
    /// ```
    fn pair_adjacent(self) -> Self::AdjacentPairs;
}
