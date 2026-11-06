//! Zero-cost representation of party-private data.
//!
//! It is often the case that in a multi-party protocol, one of the two parties
//! has access to information that the other does not.
//!
//! Rather than duplicating functionality between two distinct implementations of these parties,
//! [`PartyPrivate`] types allow for functionality to be shared between the parties.

use crate::{
    GenericParty, OppositeParty,
    either::{
        PartyEither, PartyEitherCopy,
        raw::{RawEither, bounds},
    },
    ty_eq::{EqualityProposition as EqProp, Witness, generics},
};
use bytemuck::TransparentWrapper;
use std::fmt::Debug;

pub mod raw {
    //! Internals of [`PartyPrivate`]s
    //!
    //! For advanced uses, just like you might need to use [`RawEither`] instead of
    //! [`PartyEither`], you might need to access the
    //! [`PartyPrivateRaw`] internals of a [`PartyPrivate`].
    //!
    //! [`PartyPrivate`] is a [`TransparentWrapper`] over [`PartyPrivateRaw`].
    use crate::{
        GenericParty, GenericWhichParty, OppositeParty, Party0, Party1,
        either::raw::{EitherBound, RawEither, bounds, is_t0, is_t1},
        ty_eq::{EqualityProposition as EqProp, Witness},
    };
    /// A zero-sized typed used to represent a value private to not the current party
    #[derive(
        bytemuck::Pod,
        bytemuck::Zeroable,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Debug,
        Default,
    )]
    #[repr(transparent)]
    pub struct PrivateToOtherParty;
    impl PrivateToOtherParty {
        /// Get a `&'a mut PrivateToOtherParty` for any `'a`
        ///
        /// For an immutable `&'a PrivateToOtherParty` you can simply write
        /// ```
        /// # use swanky_party::private::raw::*;
        /// let x: &'static PrivateToOtherParty = &PrivateToOtherParty;
        /// ```
        ///
        /// But for a mutable reference, you can't [due to Rust not supporting it yet](https://github.com/rust-lang/rust/blob/c018ae5389c49cc4bcb8343d80dd8e7323325410/compiler/rustc_mir_transform/src/promote_consts.rs#L411-L413)
        ///
        /// ```compile_fail
        /// # use swanky_party::private::raw::*;
        /// let x: &'static mut PrivateToOtherParty = &mut PrivateToOtherParty;
        /// ```
        ///
        /// `ref_mut()` lets you generate `&'a mut PrivateToOtherParty` just like you can for
        /// immutable references.
        #[inline]
        pub fn ref_mut<'a>() -> &'a mut Self {
            // Due to https://github.com/rust-lang/rust/blob/c018ae5389c49cc4bcb8343d80dd8e7323325410/compiler/rustc_mir_transform/src/promote_consts.rs#L411-L413
            // we need to use unsafe code or Box::new() for this.
            //
            // Box::new() doesn't actually do any allocation for a zero-sized type.
            //
            // This trick due to @spernsteiner
            Box::leak(Box::new(PrivateToOtherParty))
        }
    }
    #[test]
    fn private_to_other_party_ref_mut_doesnt_leak() {
        assert_eq!(
            PrivateToOtherParty::ref_mut(),
            PrivateToOtherParty::ref_mut()
        );
        assert_eq!(
            PrivateToOtherParty::ref_mut() as *mut PrivateToOtherParty,
            std::ptr::dangling_mut()
        );
    }

    /// Evidence that a [`PartyPrivate`] is either full or empty.
    ///
    /// Constructed via [`private_which`]
    #[derive(Clone, Copy, Debug)]
    pub enum PrivateWhich<Full, Empty> {
        /// Evidence that the [`PartyPrivate`] is full
        ///
        /// i.e. evidence that `PrivateTo == P`
        Full(Full),
        /// Evidence that the [`PartyPrivate`] is empty
        ///
        /// i.e. evidence that `OppositeParty<PrivateTo> == P`
        Empty(Empty),
    }
    /// Construct a [`PrivateWhich`] to prove whether a
    /// [`PartyPrivate<PrivateTo, P, _>`](PartyPrivate) would be full or empty.
    #[inline(always)]
    pub const fn private_which<
        PrivateTo: GenericParty<PartySystem = P::PartySystem>,
        P: GenericParty,
    >() -> PrivateWhich<
        Witness<impl EqProp<PrivateTo, P>>,
        Witness<impl EqProp<OppositeParty<PrivateTo>, P>>,
    > {
        match (PrivateTo::GENERIC_WHICH, P::GENERIC_WHICH) {
            (GenericWhichParty::Party0(a), GenericWhichParty::Party0(b)) => {
                PrivateWhich::Full(a.and_then(b.sym()).join_left().join())
            }
            (GenericWhichParty::Party0(a), GenericWhichParty::Party1(b)) => PrivateWhich::Empty(
                is_t0::<bounds::GenericParty, PrivateTo, Party1<P>, Party0<P>>(a)
                    .sym()
                    .and_then(b.sym())
                    .join_left()
                    .join(),
            ),
            (GenericWhichParty::Party1(a), GenericWhichParty::Party0(b)) => PrivateWhich::Empty(
                is_t1::<bounds::GenericParty, PrivateTo, Party1<P>, Party0<P>>(a)
                    .sym()
                    .and_then(b.sym())
                    .join_right()
                    .join(),
            ),
            (GenericWhichParty::Party1(a), GenericWhichParty::Party1(b)) => {
                PrivateWhich::Full(a.and_then(b.sym()).join_right().join())
            }
        }
    }

    /// The [`RawEither`] which [`PartyPrivate`] is a [`TransparentWrapper`] to
    pub type PartyPrivateRaw<Bound, PrivateTo, P, T> = RawEither<
        Bound,
        PrivateTo,
        RawEither<Bound, P, T, PrivateToOtherParty>,
        RawEither<Bound, P, PrivateToOtherParty, T>,
    >;

    /// Given that `PrivateTo == P`, conclude that `T == PartyPrivateRaw<B, PrivateTo, P, T>`
    #[inline(always)]
    pub const fn private_full<
        B: EitherBound<T, PrivateToOtherParty>
            + EitherBound<PrivateToOtherParty, T>
            + EitherBound<
                RawEither<B, P, T, PrivateToOtherParty>,
                RawEither<B, P, PrivateToOtherParty, T>,
            >,
        PrivateTo: GenericParty<PartySystem = P::PartySystem>,
        P: GenericParty,
        T,
    >(
        w: Witness<impl EqProp<PrivateTo, P>>,
    ) -> Witness<impl EqProp<T, PartyPrivateRaw<B, PrivateTo, P, T>>> {
        let _ = w;
        match const { (PrivateTo::GENERIC_WHICH, P::GENERIC_WHICH) } {
            (GenericWhichParty::Party0(a), GenericWhichParty::Party0(b)) => is_t0::<B, _, _, _>(b)
                .and_then(is_t0::<B, _, _, _>(a))
                .join_left()
                .join(),
            (GenericWhichParty::Party1(a), GenericWhichParty::Party1(b)) => is_t1::<B, _, _, _>(b)
                .and_then(is_t1::<B, _, _, _>(a))
                .join_right()
                .join(),
            (GenericWhichParty::Party0(_), GenericWhichParty::Party1(_))
            | (GenericWhichParty::Party1(_), GenericWhichParty::Party0(_)) => unreachable!(),
        }
    }
    /// Given that `OppositeParty<PrivateTo> == P`, conclude that
    /// `PrivateToOtherParty == PartyPrivateRaw<B, PrivateTo, P, T>`
    #[inline(always)]
    pub const fn private_empty<
        B: EitherBound<T, PrivateToOtherParty>
            + EitherBound<PrivateToOtherParty, T>
            + EitherBound<
                RawEither<B, P, T, PrivateToOtherParty>,
                RawEither<B, P, PrivateToOtherParty, T>,
            >,
        PrivateTo: GenericParty<PartySystem = P::PartySystem>,
        P: GenericParty,
        T,
    >(
        w: Witness<impl EqProp<OppositeParty<PrivateTo>, P>>,
    ) -> Witness<impl EqProp<PrivateToOtherParty, PartyPrivateRaw<B, PrivateTo, P, T>>> {
        let _ = w;
        match const { (PrivateTo::GENERIC_WHICH, P::GENERIC_WHICH) } {
            (GenericWhichParty::Party0(a), GenericWhichParty::Party1(b)) => is_t1::<B, _, _, _>(b)
                .and_then(is_t0::<B, _, _, _>(a))
                .join_left()
                .join(),
            (GenericWhichParty::Party1(a), GenericWhichParty::Party0(b)) => is_t0::<B, _, _, _>(b)
                .and_then(is_t1::<B, _, _, _>(a))
                .join_right()
                .join(),
            (GenericWhichParty::Party0(_), GenericWhichParty::Party0(_))
            | (GenericWhichParty::Party1(_), GenericWhichParty::Party1(_)) => unreachable!(),
        }
    }
}
use raw::{
    PartyPrivateRaw, PrivateToOtherParty, PrivateWhich, private_empty, private_full, private_which,
};

macro_rules! private {
    ($(
        $(#[$meta:meta])*
        type $PartyPrivate:ident$(: $Copy:ident)? => $bound:ty;
        type $PartyEither:ident;
    )*) => {$(
        #[derive(TransparentWrapper)]
        #[repr(transparent)]
        #[doc=concat!(
            "`", stringify!($PartyPrivate), "` is a wrapper type which is `repr(transparent)` to ",
            "`T` if `PrivateTo == P` and [`PrivateToOtherParty`] otherwise"
        )]
        $(#[$meta])*
        pub struct $PartyPrivate<
            PrivateTo: GenericParty<PartySystem = P::PartySystem>,
            P: GenericParty,
            T$(: $Copy)?,
        >(PartyPrivateRaw<$bound, PrivateTo, P, T>);
        impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T$(: $Copy)?>
            $PartyPrivate<PrivateTo, P, T>
        {
            /// Construct a new `PartyPrivate`. If `P == PrivateTo` it'll contain `t`, otherwise
            /// it'll be empty.
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, private::*};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// // Values that are private only to Alice.
            /// type AlicePrivate<P, T> = PartyPrivate<Alice, P, T>;
            /// let p1: AlicePrivate<Alice, i32> = PartyPrivate::new(12);
            /// // p2 is empty because this value is private to Alice, but the current party is Bob
            /// let p2: AlicePrivate<Bob, i32> = PartyPrivate::new(13);
            /// ```
            #[inline(always)]
            pub fn new(t: T) -> Self {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(e) => Self(private_full::<$bound, _, _, _>(e).cast(t)),
                    PrivateWhich::Empty(e) => Self::empty(e),
                }
            }
            /// Construct a new `PartyPrivate`. If `P == PrivateTo`
            /// it'll contain `constructor()`, otherwise it'll be empty.
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, private::*};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// // Values that are private only to Alice.
            /// type AlicePrivate<P, T> = PartyPrivate<Alice, P, T>;
            /// let p1: AlicePrivate<Alice, i32> = PartyPrivate::new_with(|| 12);
            /// // p2 is empty because this value is private to Alice, but the current party is Bob
            /// let p2: AlicePrivate<Bob, i32> = PartyPrivate::new_with(|| 13);
            /// ```
            #[inline(always)]
            pub fn new_with(constructor: impl FnOnce() -> T) -> Self {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(_) => Self::new(constructor()),
                    PrivateWhich::Empty(e) => Self::empty(e),
                }
            }
            /// Construct an empty `PartyPrivate`, given that `PrivateTo != P`
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, private::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// // Values that are private only to Alice.
            /// type AlicePrivate<P, T> = PartyPrivate<Alice, P, T>;
            /// let p: AlicePrivate<Bob, i32> = PartyPrivate::empty(Witness::EQUAL_TYPES);
            /// ```
            #[inline(always)]
            pub fn empty(e: Witness<impl EqProp<OppositeParty<PrivateTo>, P>>) -> Self {
                Self(private_empty::<$bound, PrivateTo, P, T>(e).cast(PrivateToOtherParty))
            }
            /// Extract the contents of a private value, given `PrivateTo = P`
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, private::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// // Values that are private only to Alice.
            /// type AlicePrivate<P, T> = PartyPrivate<Alice, P, T>;
            /// let p: AlicePrivate<Alice, i32> = PartyPrivate::new(13);
            /// assert_eq!(p.into_inner(Witness::EQUAL_TYPES), 13);
            /// ```
            #[inline(always)]
            pub fn into_inner(self, e: Witness<impl EqProp<PrivateTo, P>>) -> T {
                private_full::<$bound, _, _, _>(e).sym().cast(self.0)
            }
            /// Convert from `&PartyPrivate<PrivateTo, P, T>` into `PartyPrivate<PrivateTo, P, &T>`
            ///
            /// This serves the same purpose as [`Option::as_ref`]
            ///
            /// This is frequently useful to _borrow_ the contents of a `PartyPrivate`.
            #[inline(always)]
            pub fn as_ref(&self) -> $PartyPrivate<PrivateTo, P, &T> {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(e) => $PartyPrivate::new(
                        private_full::<$bound, _, _, _>(e)
                            .sym()
                            .with_generic::<generics::Ref, _, _>()
                            .cast(&self.0)
                    ),
                    PrivateWhich::Empty(e) => $PartyPrivate::empty(e),
                }
            }
            /// Convert from `&mut PartyPrivate<PrivateTo, P, T>` into `PartyPrivate<PrivateTo, P, &mut T>`
            ///
            /// This serves the same purpose as [`Option::as_mut`]
            ///
            /// This is frequently useful to _borrow_ the contents of a `PartyPrivate`.
            #[inline(always)]
            pub fn as_mut(&mut self) -> PartyPrivate<PrivateTo, P, &mut T> {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(e) => PartyPrivate::new(
                        private_full::<$bound, _, _, _>(e)
                            .sym()
                            .with_generic::<generics::RefMut, _, _>()
                            .cast(&mut self.0)
                    ),
                    PrivateWhich::Empty(e) => PartyPrivate::empty(e),
                }
            }
            /// Create a new `PartyPrivate` by running `f` on the
            /// contents if `P == PrivateTo`.
            #[inline(always)]
            pub fn map<U$(: $Copy)?>(self, f: impl FnOnce(T) -> U) -> $PartyPrivate<PrivateTo, P, U> {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(ev) => $PartyPrivate::new(f(self.into_inner(ev))),
                    PrivateWhich::Empty(ev) => $PartyPrivate::empty(ev),
                }
            }

            /// Combine `self` with another `PartyPrivate` by zipping them.
            ///
            /// Compare to [`Option::zip`].
            #[inline(always)]
            pub fn zip<U$(: $Copy)?>(
                self,
                other: $PartyPrivate<PrivateTo, P, U>,
            ) ->$PartyPrivate<PrivateTo, P, (T, U)> {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(ev) => {
                        $PartyPrivate::new((self.into_inner(ev), other.into_inner(ev)))
                    }
                    PrivateWhich::Empty(ev) => $PartyPrivate::empty(ev),
                }
            }
            /// Combine `self` with another `PartyPrivate` by zipping
            /// them with `mapper`.
            ///
            /// Compare to [`Option::zip_with`].
            #[inline(always)]
            pub fn zip_with<Tx$(: $Copy)?, U$(: $Copy)?>(
                self,
                other: $PartyPrivate<PrivateTo, P, Tx>,
                mapper: impl FnOnce(T, Tx) -> U,
            ) ->$PartyPrivate<PrivateTo, P, U> {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(ev) => {
                        $PartyPrivate::new(mapper(self.into_inner(ev), other.into_inner(ev)))
                    }
                    PrivateWhich::Empty(ev) => $PartyPrivate::empty(ev),
                }
            }

            /// Return the private value (if `self` is private to
            /// `P`), or else run the given closure.
            pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(ev) => self.into_inner(ev),
                    PrivateWhich::Empty(_) => f(),
                }
            }

            /// Return the private value (if `self` is private to
            /// `P`), or else return `None`.
            pub fn into_option(self) -> Option<T> {
                self.map(Some).unwrap_or_else(|| None)
            }
        }
        impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Default $(+ $Copy)?>
            Default for $PartyPrivate<PrivateTo, P, T>
        {
            #[inline(always)]
            fn default() -> Self {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(_) => Self::new(T::default()),
                    PrivateWhich::Empty(e) => Self::empty(e),
                }
            }
        }
        impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Debug $(+ $Copy)?>
            Debug for $PartyPrivate<PrivateTo, P, T>
        {
            #[inline(always)]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(e) => writeln!(f, "{:?}", self.as_ref().into_inner(e)),
                    PrivateWhich::Empty(_) => writeln!(f, "{:?}", PrivateToOtherParty),
                }
            }
        }
        impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T $(: $Copy)?, E $(: $Copy)?> $PartyPrivate<PrivateTo, P, Result<T, E>> {
            /// Convert a `PartyPrivate<PrivateTo, P, Result<T, E>>`
            /// to a `Result<PartyPrivate<PrivateTo, P, T>, E>` in the
            /// natural way.
            pub fn lift_result(self) -> Result<$PartyPrivate<PrivateTo, P, T>, E> {
                Ok(match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(e) => $PartyPrivate::new(self.into_inner(e)?),
                    PrivateWhich::Empty(e) => $PartyPrivate::empty(e),
                })
            }
        }
        unsafe impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Send $(+ $Copy)?>
            Send for $PartyPrivate<PrivateTo, P, T>
        {}
        unsafe impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Sync $(+ $Copy)?>
            Sync for $PartyPrivate<PrivateTo, P, T>
        {}
        impl<'a, PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T$(: $Copy)?>
            From<&'a $PartyPrivate<PrivateTo, P, T>> for $PartyPrivate<PrivateTo, P, &'a T>
        {
            #[inline(always)]
            fn from(x: &'a $PartyPrivate<PrivateTo, P, T>) -> Self {
                x.as_ref()
            }
        }
        impl<'a, PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T$(: $Copy)?>
            From<$PartyPrivate<PrivateTo, P, &'a T>> for &'a $PartyPrivate<PrivateTo, P, T>
        {
            #[inline(always)]
            fn from(x: $PartyPrivate<PrivateTo, P, &'a T>) -> Self {
                TransparentWrapper::wrap_ref(match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(e) => {
                        private_full::<$bound, PrivateTo, P, T>(e)
                            .with_generic::<generics::Ref, _, _>()
                            .cast(x.into_inner(e))
                    }
                    PrivateWhich::Empty(e) => {
                        private_empty::<$bound, PrivateTo, P, T>(e)
                            .with_generic::<generics::Ref, _, _>()
                            .cast(&PrivateToOtherParty)
                    }
                })
            }
        }
        impl<'a, PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T$(: $Copy)?>
            From<&'a mut $PartyPrivate<PrivateTo, P, T>> for PartyPrivate<PrivateTo, P, &'a mut T>
        {
            #[inline(always)]
            fn from(x: &'a mut $PartyPrivate<PrivateTo, P, T>) -> Self {
                x.as_mut()
            }
        }
        impl<'a, PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T$(: $Copy)?>
            From<PartyPrivate<PrivateTo, P, &'a mut T>> for &'a mut $PartyPrivate<PrivateTo, P, T>
        {
            #[inline(always)]
            fn from(x: PartyPrivate<PrivateTo, P, &'a mut T>) -> Self {
                TransparentWrapper::wrap_mut(match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(e) => {
                        private_full::<$bound, PrivateTo, P, T>(e)
                            .with_generic::<generics::RefMut, _, _>()
                            .cast(x.into_inner(e))
                    }
                    PrivateWhich::Empty(e) => {
                        private_empty::<$bound, PrivateTo, P, T>(e)
                            .with_generic::<generics::RefMut, _, _>()
                            .cast(PrivateToOtherParty::ref_mut())
                    }
                })
            }
        }
        impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T$(: $Copy)?>
            From<$PartyPrivate<PrivateTo, P, T>> for Option<T>
        {
            #[inline(always)]
            fn from(p: $PartyPrivate<PrivateTo, P, T>) -> Self {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(e) => Some(p.into_inner(e)),
                    PrivateWhich::Empty(_) => None,
                }
            }
        }
        impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T0$(: $Copy)?, T1$(: $Copy)?>
            From<$PartyEither<P, T0, T1>>
            for $PartyPrivate<PrivateTo, P, RawEither<$bound, PrivateTo, T0, T1>>
        {
            #[inline(always)]
            fn from(value: $PartyEither<P, T0, T1>) -> Self {
                match const { private_which::<PrivateTo, P>() } {
                    PrivateWhich::Full(w) => Self::new(value.into_inner(w.sym())),
                    PrivateWhich::Empty(w) => Self::empty(w),
                }
            }
        }
    )*};
}
impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy> Clone
    for PartyPrivateCopy<PrivateTo, P, T>
{
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}
impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy> Copy
    for PartyPrivateCopy<PrivateTo, P, T>
{
}
impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Clone> Clone
    for PartyPrivate<PrivateTo, P, T>
{
    #[inline(always)]
    fn clone(&self) -> Self {
        self.as_ref().map(|x| x.clone())
    }
}

private! {
    type PartyPrivate => bounds::Any;
    type PartyEither;
    /// # Copy
    /// [`PartyPrivateCopy`] is identical to [`PartyPrivate`] except that it implements [`Copy`] (and
    /// correspondingly requires `T` to implement `Copy`, too).
    ///
    /// To convert between [`PartyPrivateCopy`] and [`PartyPrivate`], you can use [`From::from`].
    ///
    /// ```
    /// # use swanky_party::{*, private::*};
    /// party_system! {
    ///     mod ps {
    ///         Alice,
    ///         Bob,
    ///     }
    /// }
    /// use ps::*;
    /// fn convert<P: Party>(e: PartyPrivate<P, Alice, i32>) -> PartyPrivateCopy<P, Alice, i32> {
    ///     e.into()
    /// }
    /// ```
    type PartyPrivateCopy: Copy => bounds::Copy;
    type PartyEitherCopy;
}

impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: PartialEq> PartialEq
    for PartyPrivate<PrivateTo, P, T>
{
    fn eq(&self, other: &Self) -> bool {
        match const { private_which::<PrivateTo, P>() } {
            PrivateWhich::Full(e) => self.as_ref().into_inner(e) == other.as_ref().into_inner(e),
            PrivateWhich::Empty(_) => true,
        }
    }
}

impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy + PartialEq>
    PartialEq for PartyPrivateCopy<PrivateTo, P, T>
{
    fn eq(&self, other: &Self) -> bool {
        match const { private_which::<PrivateTo, P>() } {
            PrivateWhich::Full(e) => self.into_inner(e) == other.into_inner(e),
            PrivateWhich::Empty(_) => true,
        }
    }
}

mod copy_conversions;

#[cfg(test)]
mod tests {
    use super::*;

    party_system! {
        mod ps {
            PartyA,
            PartyB,
        }
    }
    use ps::{PartyA, PartyB};

    #[test]
    fn private_which_exhaustive() {
        let w = private_which::<PartyA, PartyA>();
        match w {
            PrivateWhich::Full(e) => assert_eq!(e.cast(PartyA), PartyA),
            PrivateWhich::Empty(_) => unreachable!(),
        }

        let w = private_which::<PartyB, PartyB>();
        match w {
            PrivateWhich::Full(e) => assert_eq!(e.cast(PartyB), PartyB),
            PrivateWhich::Empty(_) => unreachable!(),
        }

        let w = private_which::<PartyB, PartyB>();
        match w {
            PrivateWhich::Full(e) => assert_eq!(e.cast(PartyB), PartyB),
            PrivateWhich::Empty(_) => unreachable!(),
        }

        let w = private_which::<PartyA, PartyB>();
        match w {
            PrivateWhich::Full(_) => unreachable!(),
            PrivateWhich::Empty(e) => assert_eq!(e.cast(PartyB), PartyB),
        }

        let w = private_which::<PartyB, PartyA>();
        match w {
            PrivateWhich::Full(_) => unreachable!(),
            PrivateWhich::Empty(e) => assert_eq!(e.cast(PartyA), PartyA),
        }
    }

    #[test]
    fn as_mut_full() {
        let p: &mut PartyPrivateCopy<PartyA, PartyA, _> = &mut PartyPrivateCopy::new(17);
        *p.as_mut().unwrap_or_else(|| unreachable!()) = 71;
        assert_eq!(p.unwrap_or_else(|| unreachable!()), 71);
    }

    #[test]
    fn as_mut_empty() {
        let p: &mut PartyPrivateCopy<PartyA, PartyB, i32> =
            &mut PartyPrivateCopy::empty(Witness::EQUAL_TYPES);
        let mut other = 0;
        *p.as_mut().unwrap_or_else(|| &mut other) = 13;
        assert_eq!(other, 13);
    }

    #[test]
    fn zip_full() {
        let p1: PartyPrivate<PartyA, PartyA, _> = PartyPrivate::new(17);
        let p2: PartyPrivate<PartyA, PartyA, _> = PartyPrivate::new(17);
        assert_eq!(p1.zip(p2), PartyPrivate::new((17, 17)));
    }

    #[test]
    fn zip_empty() {
        let p1: PartyPrivate<PartyA, PartyB, i32> = PartyPrivate::empty(Witness::EQUAL_TYPES);
        let p2: PartyPrivate<PartyA, PartyB, i32> = PartyPrivate::empty(Witness::EQUAL_TYPES);
        assert_eq!(p1.zip(p2), PartyPrivate::empty(Witness::EQUAL_TYPES));
    }

    #[test]
    fn zip_with_full() {
        let p1: PartyPrivateCopy<PartyA, PartyA, _> = PartyPrivateCopy::new(17);
        let p2: PartyPrivateCopy<PartyA, PartyA, _> = PartyPrivateCopy::new(71);
        let p3: PartyPrivateCopy<PartyA, PartyA, _> = PartyPrivateCopy::new(88);
        assert_eq!(p1.zip_with(p2, |n1, n2| n1 + n2), p3);
    }

    #[test]
    fn zip_with_empty() {
        let p1: PartyPrivateCopy<PartyA, PartyB, _> = PartyPrivateCopy::new(17);
        let p2: PartyPrivateCopy<PartyA, PartyB, _> = PartyPrivateCopy::new(71);
        assert_eq!(
            p1.zip_with(p2, |n1, n2| n1 + n2),
            PartyPrivateCopy::empty(Witness::EQUAL_TYPES)
        );
    }

    #[test]
    fn into_option_full() {
        assert!(
            PartyPrivateCopy::<PartyA, PartyA, _>::new(17)
                .into_option()
                .is_some()
        );
    }

    #[test]
    fn into_option_empty() {
        assert!(
            PartyPrivateCopy::<PartyA, PartyB, _>::new(17)
                .into_option()
                .is_none()
        );
    }

    #[test]
    fn private_formatting() {
        let p_full: PartyPrivateCopy<PartyA, PartyA, _> = PartyPrivateCopy::new(17);
        let p_empty: PartyPrivateCopy<PartyA, PartyB, i32> = PartyPrivateCopy::default();

        assert_eq!(format!("{p_full:?}"), "17\n".to_string());
        assert_eq!(format!("{p_empty:?}"), "PrivateToOtherParty\n".to_string());
    }

    #[test]
    fn lift_result_full() {
        let p: PartyPrivateCopy<PartyA, PartyA, Result<i32, ()>> = PartyPrivateCopy::new(Ok(17));
        assert!(p.lift_result().is_ok());

        let p: PartyPrivateCopy<PartyA, PartyA, Result<i32, ()>> = PartyPrivateCopy::new(Err(()));
        assert!(p.lift_result().is_err());
    }

    #[test]
    fn lift_result_empty() {
        let p: PartyPrivateCopy<PartyA, PartyB, Result<i32, ()>> = PartyPrivateCopy::new(Err(()));
        assert!(p.lift_result().is_ok());
    }

    #[test]
    fn ref_private_to_private_ref() {
        let p: &PartyPrivateCopy<PartyA, PartyA, _> = &PartyPrivateCopy::new(17);
        assert_eq!(
            *PartyPrivateCopy::<PartyA, PartyA, &i32>::from(p).into_inner(Witness::EQUAL_TYPES),
            17
        );
    }

    #[test]
    fn private_ref_to_ref_private() {
        let p: PartyPrivateCopy<PartyA, PartyA, &i32> = PartyPrivateCopy::new(&17);
        assert_eq!(
            <&PartyPrivateCopy<PartyA, PartyA, i32>>::from(p).into_inner(Witness::EQUAL_TYPES),
            17
        );

        let p: PartyPrivateCopy<PartyA, PartyB, &i32> =
            PartyPrivateCopy::empty(Witness::EQUAL_TYPES);
        assert_eq!(
            <&PartyPrivateCopy<PartyA, PartyB, i32>>::from(p).unwrap_or_else(|| 17),
            17
        );
    }

    #[test]
    fn mut_ref_private_to_private_mut_ref() {
        let p: &mut PartyPrivate<PartyA, PartyA, _> = &mut PartyPrivate::new(17);
        *PartyPrivate::<PartyA, PartyA, &mut i32>::from(&mut *p).into_inner(Witness::EQUAL_TYPES) =
            71;
        assert_eq!(p.clone().into_inner(Witness::EQUAL_TYPES), 71);
    }

    #[test]
    fn private_mut_ref_to_mut_ref_private() {
        let mut x = 17;
        let p: PartyPrivate<PartyA, PartyA, &mut i32> = PartyPrivate::new(&mut x);
        assert_eq!(
            <&mut PartyPrivate<PartyA, PartyA, i32>>::from(p)
                .clone()
                .into_inner(Witness::EQUAL_TYPES),
            17
        );

        let p: PartyPrivate<PartyA, PartyB, &mut i32> = PartyPrivate::empty(Witness::EQUAL_TYPES);
        assert_eq!(
            <&mut PartyPrivate<PartyA, PartyB, i32>>::from(p)
                .clone()
                .unwrap_or_else(|| 17),
            17
        );
    }

    #[test]
    fn private_to_option() {
        assert!(Option::<i32>::from(PartyPrivateCopy::<PartyA, PartyA, _>::new(17)).is_some());
        assert!(Option::<i32>::from(PartyPrivateCopy::<PartyA, PartyB, _>::new(17)).is_none());
    }

    #[test]
    fn party_either_to_private() {
        let p: PartyEitherCopy<PartyA, i32, ()> = PartyEitherCopy::new(Witness::EQUAL_TYPES, 17);
        assert_eq!(
            PartyPrivateCopy::<PartyA, PartyA, i32>::from(p).unwrap_or_else(|| unreachable!()),
            17
        );

        let p: PartyEitherCopy<PartyB, i32, ()> = PartyEitherCopy::new(Witness::EQUAL_TYPES, ());
        assert_eq!(
            PartyPrivateCopy::<PartyB, PartyB, ()>::from(p).unwrap_or_else(|| unreachable!()),
            ()
        );

        let p: PartyEitherCopy<PartyB, i32, ()> = PartyEitherCopy::new(Witness::EQUAL_TYPES, ());
        assert_eq!(
            PartyPrivateCopy::<PartyA, PartyB, i32>::from(p).unwrap_or_else(|| 17),
            17
        );
    }
}
