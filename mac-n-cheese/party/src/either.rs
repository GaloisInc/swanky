use std::io::{Read, Write};

use super::*;

pub(super) mod internal {
    use super::*;
    pub unsafe trait EitherStorageTrait<P, V> {
        // These functions will panic if called on the wrong variant.
        fn new_prover(p: P) -> Self;
        fn into_prover(self) -> P;
        fn ref_prover(&self) -> &P;
        fn mut_prover(&mut self) -> &mut P;

        fn new_verifier(v: V) -> Self;
        fn into_verifier(self) -> V;
        fn ref_verifier(&self) -> &V;
        fn mut_verifier(&mut self) -> &mut V;
    }
    pub unsafe trait PartyEitherInternal {
        type EitherStorage<Prover, Verifier>: EitherStorageTrait<Prover, Verifier>;
        type EitherStorageCopy<Prover: Copy, Verifier: Copy>: EitherStorageTrait<Prover, Verifier>
            + Copy;
    }
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct EitherStorage<Pa: Party, T>(T, PhantomData<Pa>);
    unsafe impl<P, V> EitherStorageTrait<P, V> for EitherStorage<Prover, P> {
        #[inline]
        fn new_prover(p: P) -> Self {
            EitherStorage(p, PhantomData)
        }
        #[inline]
        fn into_prover(self) -> P {
            self.0
        }
        #[inline]
        fn ref_prover(&self) -> &P {
            &self.0
        }
        #[inline]
        fn mut_prover(&mut self) -> &mut P {
            &mut self.0
        }

        #[cold]
        fn new_verifier(_v: V) -> Self {
            unreachable!()
        }
        #[cold]
        fn into_verifier(self) -> V {
            unreachable!()
        }
        #[cold]
        fn ref_verifier(&self) -> &V {
            unreachable!()
        }
        #[cold]
        fn mut_verifier(&mut self) -> &mut V {
            unreachable!()
        }
    }
    unsafe impl<P, V> EitherStorageTrait<P, V> for EitherStorage<Verifier, V> {
        #[cold]
        fn new_prover(_p: P) -> Self {
            unreachable!()
        }
        #[cold]
        fn into_prover(self) -> P {
            unreachable!()
        }
        #[cold]
        fn ref_prover(&self) -> &P {
            unreachable!()
        }
        #[cold]
        fn mut_prover(&mut self) -> &mut P {
            unreachable!()
        }

        #[inline]
        fn new_verifier(v: V) -> Self {
            EitherStorage(v, PhantomData)
        }
        #[inline]
        fn into_verifier(self) -> V {
            self.0
        }
        #[inline]
        fn ref_verifier(&self) -> &V {
            &self.0
        }
        #[inline]
        fn mut_verifier(&mut self) -> &mut V {
            &mut self.0
        }
    }
}
use internal::*;

macro_rules! define_prover_either {
    ($PartyEither:ident $(: $Copy:ident)? => $EitherStorage:ident) => {
        #[repr(transparent)]
        pub struct $PartyEither<Pa: Party, P $(: $Copy)?, V $(: $Copy)?> {
            contents: Pa::$EitherStorage<P, V>,
        }
        impl<Pa: Party, P $(: $Copy)?, V $(: $Copy)?> $PartyEither<Pa, P, V> {
            pub fn prover_new(_ev: IsParty<Pa, Prover>, x: P) -> Self {
                Self { contents: Pa::$EitherStorage::<P, V>::new_prover(x) }
            }
            pub fn verifier_new(_ev: IsParty<Pa, Verifier>, x: V) -> Self {
                Self { contents: Pa::$EitherStorage::<P, V>::new_verifier(x) }
            }
            pub fn prover_into(self, _ev: IsParty<Pa, Prover>) -> P {
                Pa::$EitherStorage::<P, V>::into_prover(self.contents)
            }
            pub fn verifier_into(self, _ev: IsParty<Pa, Verifier>) -> V {
                Pa::$EitherStorage::<P, V>::into_verifier(self.contents)
            }
            pub fn as_ref(&self) -> $PartyEither<Pa, &P, &V> {
                match Pa::WHICH {
                    WhichParty::Prover(e) =>
                        $PartyEither::prover_new(e, Pa::$EitherStorage::<P, V>::ref_prover(&self.contents)),
                    WhichParty::Verifier(e) =>
                        $PartyEither::verifier_new(e, Pa::$EitherStorage::<P, V>::ref_verifier(&self.contents)),
                }
            }
            pub fn as_mut(&mut self) -> PartyEither<Pa, &mut P, &mut V> {
                match Pa::WHICH {
                    WhichParty::Prover(e) =>
                        PartyEither::prover_new(e, Pa::$EitherStorage::<P, V>::mut_prover(&mut self.contents)),
                    WhichParty::Verifier(e) =>
                        PartyEither::verifier_new(e, Pa::$EitherStorage::<P, V>::mut_verifier(&mut self.contents)),
                }
            }
            pub fn zip<
                P2 $(: $Copy)?,
                V2 $(: $Copy)?,
            >(self, x: $PartyEither<Pa, P2, V2>) -> $PartyEither<Pa, (P, P2), (V, V2)> {
                match Pa::WHICH {
                    WhichParty::Prover(e) =>$PartyEither::prover_new(e, (
                        self.prover_into(e),
                        x.prover_into(e),
                    )),
                    WhichParty::Verifier(e) =>$PartyEither::verifier_new(e, (
                        self.verifier_into(e),
                        x.verifier_into(e),
                    )),
                }
            }
            pub fn map<
                P2 $(: $Copy)?,
                V2 $(: $Copy)?,
                PF: FnOnce(P) -> P2,
                VF: FnOnce(V) -> V2,
            >(self, pf: PF, vf: VF) -> $PartyEither<Pa, P2, V2> {
                match Pa::WHICH {
                    WhichParty::Prover(e) => $PartyEither::prover_new(e, pf(self.prover_into(e))),
                    WhichParty::Verifier(e) => $PartyEither::verifier_new(e, vf(self.verifier_into(e))),
                }
            }
        }
        unsafe impl<Pa: Party, P: Send $(+ $Copy)?, V: Send $(+ $Copy)?> Send for $PartyEither<Pa, P, V> {}
        unsafe impl<Pa: Party, P: Sync $(+ $Copy)?, V: Sync $(+ $Copy)?> Sync for $PartyEither<Pa, P, V> {}
        impl<Pa: Party, P: Default $(+ $Copy)?, V: Default $(+ $Copy)?> Default for $PartyEither<Pa, P, V> {
            fn default() -> Self {
                match Pa::WHICH {
                    WhichParty::Prover(e) => $PartyEither::prover_new(e, P::default()),
                    WhichParty::Verifier(e) => $PartyEither::verifier_new(e, V::default()),
                }
            }
        }
        impl<Pa: Party, P: Clone $(+ $Copy)?, V: Clone $(+ $Copy)?> Clone for $PartyEither<Pa, P, V> {
            fn clone(&self) -> Self {
                match Pa::WHICH {
                    WhichParty::Prover(e) =>
                        $PartyEither::prover_new(e, self.as_ref().prover_into(e).clone()),
                    WhichParty::Verifier(e) =>
                        $PartyEither::verifier_new(e, self.as_ref().verifier_into(e).clone()),
                }
            }
        }
        unsafe impl<P $(: $Copy)?, V $(: $Copy)?> bytemuck::TransparentWrapper<P> for $PartyEither<Prover, P, V> {}
        unsafe impl<P $(: $Copy)?, V $(: $Copy)?> bytemuck::TransparentWrapper<V> for $PartyEither<Verifier, P, V> {}
        // TODO: I think we can do this without unsafe?
        /*impl<'a, Pa: Party, P $(: $Copy)?, V $(: $Copy)?> From<&'a [$PartyEither<Pa, P, V>]> for $PartyEither<Pa, &'a [P], &'a [V]> {
            fn from(slice: &'a [$PartyEither<Pa, P, V>]) -> Self {
                match Pa::WHICH {
                    WhichParty::Prover(e) => {
                        Self::prover_new(e, unsafe {
                            std::slice::from_raw_parts(
                                slice.as_ptr() as *const P,
                                slice.len()
                            )
                        })
                    }
                    WhichParty::Verifier(e) => {
                        Self::verifier_new(e, unsafe {
                            std::slice::from_raw_parts(
                                slice.as_ptr() as *const V,
                                slice.len()
                            )
                        })
                    }
                }
            }
        }*/
        impl<'a, Pa: Party, P $(: $Copy)?, V $(: $Copy)?> $PartyEither<Pa, &'a [P], &'a [V]> {
            pub fn pull_either_outside(slice: &'a [$PartyEither<Pa, P, V>]) -> Self {
                match Pa::WHICH {
                    WhichParty::Prover(e) => {
                        Self::prover_new(e, unsafe {
                            std::slice::from_raw_parts(
                                slice.as_ptr() as *const P,
                                slice.len()
                            )
                        })
                    }
                    WhichParty::Verifier(e) => {
                        Self::verifier_new(e, unsafe {
                            std::slice::from_raw_parts(
                                slice.as_ptr() as *const V,
                                slice.len()
                            )
                        })
                    }
                }
            }
            pub fn push_either_inside(self) -> &'a [$PartyEither<Pa, P, V>] {
                match Pa::WHICH {
                    WhichParty::Prover(e) => {
                        let slice = self.prover_into(e);
                        unsafe {
                            std::slice::from_raw_parts(
                                slice.as_ptr() as *const $PartyEither<Pa, P, V>,
                                slice.len()
                            )
                        }
                    }
                    WhichParty::Verifier(e) => {
                        let slice = self.verifier_into(e);
                        unsafe {
                            std::slice::from_raw_parts(
                                slice.as_ptr() as *const $PartyEither<Pa, P, V>,
                                slice.len()
                            )
                        }
                    }
                }
            }
        }
    };
}

define_prover_either!(PartyEither => EitherStorage);
define_prover_either!(PartyEitherCopy: Copy => EitherStorageCopy);
impl<Pa: Party, P: Copy, V: Copy> Copy for PartyEitherCopy<Pa, P, V> {}

unsafe impl PartyEitherInternal for Prover {
    type EitherStorage<P, V> = EitherStorage<Self, P>;
    type EitherStorageCopy<P: Copy, V: Copy> = EitherStorage<Self, P>;
}
unsafe impl PartyEitherInternal for Verifier {
    type EitherStorage<P, V> = EitherStorage<Self, V>;
    type EitherStorageCopy<P: Copy, V: Copy> = EitherStorage<Self, V>;
}

// TODO: fix these impls
impl<Pa: Party, P: Copy, V: Copy> PartyEither<Pa, P, V> {
    pub fn into_copy(self) -> PartyEitherCopy<Pa, P, V> {
        match Pa::WHICH {
            WhichParty::Prover(e) => PartyEitherCopy::prover_new(e, self.prover_into(e)),
            WhichParty::Verifier(e) => PartyEitherCopy::verifier_new(e, self.verifier_into(e)),
        }
    }
}
impl<Pa: Party, P: Copy, V: Copy> From<PartyEither<Pa, P, V>> for PartyEitherCopy<Pa, P, V> {
    fn from(x: PartyEither<Pa, P, V>) -> Self {
        match Pa::WHICH {
            WhichParty::Prover(e) => PartyEitherCopy::prover_new(e, x.prover_into(e)),
            WhichParty::Verifier(e) => PartyEitherCopy::verifier_new(e, x.verifier_into(e)),
        }
    }
}
impl<Pa: Party, P: Copy, V: Copy> From<PartyEitherCopy<Pa, P, V>> for PartyEither<Pa, P, V> {
    fn from(x: PartyEitherCopy<Pa, P, V>) -> Self {
        match Pa::WHICH {
            WhichParty::Prover(e) => PartyEither::prover_new(e, x.prover_into(e)),
            WhichParty::Verifier(e) => PartyEither::verifier_new(e, x.verifier_into(e)),
        }
    }
}

unsafe impl<Pa: Party, P: Copy + Zeroable, V: Copy + Zeroable> Zeroable
    for PartyEitherCopy<Pa, P, V>
{
}
unsafe impl<Pa: Party, P: Copy + Pod, V: Copy + Pod> Pod for PartyEitherCopy<Pa, P, V> {}

impl<'a, Pa: Party, P, V> PartyEither<Pa, &'a mut [P], &'a mut [V]> {
    pub fn pull_either_outside(slice: &'a mut [PartyEither<Pa, P, V>]) -> Self {
        match Pa::WHICH {
            WhichParty::Prover(e) => Self::prover_new(e, unsafe {
                std::slice::from_raw_parts_mut(slice.as_ptr() as *mut P, slice.len())
            }),
            WhichParty::Verifier(e) => Self::verifier_new(e, unsafe {
                std::slice::from_raw_parts_mut(slice.as_ptr() as *mut V, slice.len())
            }),
        }
    }
    // TODO: there ought to be a better way of doing this.
    pub fn pull_either_outside_copy(slice: &'a mut [PartyEitherCopy<Pa, P, V>]) -> Self
    where
        P: Copy,
        V: Copy,
    {
        match Pa::WHICH {
            WhichParty::Prover(e) => Self::prover_new(e, unsafe {
                std::slice::from_raw_parts_mut(slice.as_ptr() as *mut P, slice.len())
            }),
            WhichParty::Verifier(e) => Self::verifier_new(e, unsafe {
                std::slice::from_raw_parts_mut(slice.as_ptr() as *mut V, slice.len())
            }),
        }
    }
    /*pub fn push_either_inside(self) -> &'a mut [$PartyEither<Pa, P, V>] {
        match Pa::WHICH {
            WhichParty::Prover(e) => {
                let slice = self.prover_into(e);
                unsafe {
                    std::slice::from_raw_parts(
                        slice.as_ptr() as *const $PartyEither<Pa, P, V>,
                        slice.len()
                    )
                }
            }
            WhichParty::Verifier(e) => {
                let slice = self.verifier_into(e);
                unsafe {
                    std::slice::from_raw_parts(
                        slice.as_ptr() as *const $PartyEither<Pa, P, V>,
                        slice.len()
                    )
                }
            }
        }
    }*/
}

impl<Pa: Party, P: Write, V: Write> Write for PartyEither<Pa, P, V> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match Pa::WHICH {
            WhichParty::Prover(e) => self.as_mut().prover_into(e).write(buf),
            WhichParty::Verifier(e) => self.as_mut().verifier_into(e).write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match Pa::WHICH {
            WhichParty::Prover(e) => self.as_mut().prover_into(e).flush(),
            WhichParty::Verifier(e) => self.as_mut().verifier_into(e).flush(),
        }
    }
}

impl<Pa: Party, P: Read, V: Read> Read for PartyEither<Pa, P, V> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match Pa::WHICH {
            WhichParty::Prover(e) => self.as_mut().prover_into(e).read(buf),
            WhichParty::Verifier(e) => self.as_mut().verifier_into(e).read(buf),
        }
    }
}
