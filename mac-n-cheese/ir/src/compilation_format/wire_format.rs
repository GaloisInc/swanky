use super::WireSize;
use crate::circuit_builder::PrototypeBuilder;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use scuttlebutt::serialization::CanonicalSerialize;
use std::{io::Write, marker::PhantomData};
use vectoreyes::array_utils::ArrayUnrolledExt;
use vectoreyes::array_utils::{ArrayUnrolledOps, UnrollableArraySize};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Wire(u64);
impl Wire {
    pub fn own_wire(idx: WireSize) -> Self {
        Wire((1 << 63) | u64::from(idx))
    }
    pub fn input_wire(which_input: WireSize, which_wire: WireSize) -> Self {
        assert_eq!(which_input >> 31, 0);
        Wire((u64::from(which_input) << 32) | u64::from(which_wire))
    }
    pub fn which_wire(&self) -> WireSize {
        self.0 as u32
    }
    // None means own wire
    pub fn which_input(&self) -> Option<WireSize> {
        let x = (self.0 >> 32) as u32;
        if (x >> 31) == 0 {
            Some(x)
        } else {
            None
        }
    }
}
impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.which_input() {
            Some(which_input) => {
                write!(f, "Wire::input_wire({which_input}, {})", self.which_wire())
            }
            None => write!(f, "Wire::own_wire({})", self.which_wire()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SupportsOwnWires {
    ProducesValues,
    OnlyConsumes,
}

pub mod simple {
    use super::*;
    #[derive(Default)]
    pub struct WireFormat<T: CanonicalSerialize, const NARGS: usize>(PhantomData<([(); NARGS], T)>);

    impl<T: CanonicalSerialize, const NARGS: usize> WireFormat<T, NARGS> {
        pub(crate) fn new_writer<'a, 'b, 'c, 'd>(
            pb: &'b mut PrototypeBuilder<'c, 'd>,
            input_sizes: &'a [WireSize],
            supports_own_wires: SupportsOwnWires,
        ) -> eyre::Result<Writer<'a, 'b, 'c, 'd, T, NARGS>> {
            Ok(Writer {
                pb,
                input_sizes,
                own_wires: 0,
                supports_own_wires,
                buf: vec![0; Self::stride()],
                phantom: PhantomData,
            })
        }

        const fn arg_stride() -> usize {
            std::mem::size_of::<u32>() * 2 + T::ByteReprLen::USIZE
        }
        const fn stride() -> usize {
            Self::arg_stride() * NARGS
        }
    }

    pub(crate) struct Writer<'a, 'b, 'c, 'd, T: CanonicalSerialize, const NARGS: usize> {
        input_sizes: &'a [WireSize],
        pb: &'b mut PrototypeBuilder<'c, 'd>,
        own_wires: WireSize,
        supports_own_wires: SupportsOwnWires,
        buf: Vec<u8>,
        phantom: PhantomData<([(); NARGS], T)>,
    }
    impl<'a, 'b, 'c, 'd, T: CanonicalSerialize, const NARGS: usize> Writer<'a, 'b, 'c, 'd, T, NARGS> {
        pub(crate) fn add_own_wires(&mut self, delta: WireSize) {
            if matches!(self.supports_own_wires, SupportsOwnWires::OnlyConsumes) {
                panic!("This wire writer was configured for only consuming");
            }
            self.own_wires = self.own_wires.checked_add(delta).unwrap();
        }
        pub(crate) fn write_wires(&mut self, wires: [(Wire, T); NARGS]) -> eyre::Result<()> {
            for (dst, (wire, t)) in self
                .buf
                .chunks_exact_mut(WireFormat::<T, NARGS>::arg_stride())
                .zip(wires.iter())
            {
                let (which_input, rest) = dst.split_at_mut(4);
                let (which_wire, fe_storage) = rest.split_at_mut(4);
                let max = if let Some(idx) = wire.which_input() {
                    which_input.copy_from_slice(&idx.to_le_bytes());
                    self.input_sizes[idx as usize]
                } else {
                    which_input.copy_from_slice(&(self.input_sizes.len() as u32).to_le_bytes());
                    self.own_wires
                };
                let ww = wire.which_wire();
                assert!(ww < max);
                which_wire.copy_from_slice(&ww.to_le_bytes());
                fe_storage.copy_from_slice(&t.to_bytes());
            }
            self.pb.write_all(&self.buf)?;
            Ok(())
        }
        /// Returns number of own wires
        pub(crate) fn finish(self) -> eyre::Result<WireSize> {
            Ok(self.own_wires)
        }
    }

    pub struct Reader<'a, T: CanonicalSerialize, const NARGS: usize> {
        buf: &'a [u8],
        phantom: PhantomData<([u8; NARGS], T)>,
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct ReadWire<T: CanonicalSerialize = ()> {
        pub which_input: u32,
        pub which_wire: u32,
        pub data: T,
    }

    impl<'a, T: CanonicalSerialize, const NARGS: usize> Reader<'a, T, NARGS> {
        pub fn new(buf: &'a [u8]) -> eyre::Result<Self> {
            eyre::ensure!(
                buf.len() % WireFormat::<T, NARGS>::stride() == 0,
                "The input buffer's length ({}) isn't a multiple of {} as is needed \
                for NARGS={NARGS}",
                buf.len(),
                WireFormat::<T, NARGS>::stride()
            );
            Ok(Reader {
                buf,
                phantom: PhantomData,
            })
        }
        pub fn len_remaining(&self) -> usize {
            self.buf.len() / WireFormat::<T, NARGS>::stride()
        }
        pub fn next(&mut self) -> eyre::Result<[ReadWire<T>; NARGS]>
        where
            ArrayUnrolledOps: UnrollableArraySize<NARGS>,
        {
            let (this, next) = self.buf.split_at(WireFormat::<T, NARGS>::stride());
            self.buf = next;
            debug_assert_eq!(this.len() / WireFormat::<T, NARGS>::arg_stride(), NARGS);
            let mut iter = this
                .chunks_exact(WireFormat::<T, NARGS>::arg_stride())
                .map(|arg| {
                    Ok(ReadWire {
                        which_input: u32::from_le_bytes(<[u8; 4]>::try_from(&arg[0..4]).unwrap()),
                        which_wire: u32::from_le_bytes(<[u8; 4]>::try_from(&arg[4..8]).unwrap()),
                        data: T::from_bytes(GenericArray::from_slice(&arg[8..]))?,
                    })
                });
            <[(); NARGS]>::array_generate(|_| ()).array_map_result(|_| iter.next().unwrap())
        }
    }
}

pub mod simd_batched {
    use vectoreyes::{
        array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
        U32x4,
    };

    use super::*;
    pub const BATCH_SIZE: usize = 4;
    #[derive(Default)]
    pub struct WireFormat<const NARGS: usize>(PhantomData<[(); NARGS]>);
    impl<const NARGS: usize> WireFormat<NARGS> {
        pub(crate) fn new_writer<'a, 'b, 'c, 'd>(
            pb: &'b mut PrototypeBuilder<'c, 'd>,
            input_sizes: &'a [WireSize],
            supports_own_wires: SupportsOwnWires,
        ) -> eyre::Result<Writer<'a, 'b, 'c, 'd, NARGS>> {
            Ok(Writer {
                pb,
                input_sizes,
                own_wires: 0,
                supports_own_wires,
                phantom: PhantomData,
            })
        }
    }

    // TODO: support compressed permutation wire format
    pub(crate) struct Writer<'a, 'b, 'c, 'd, const NARGS: usize> {
        input_sizes: &'a [WireSize],
        pb: &'b mut PrototypeBuilder<'c, 'd>,
        own_wires: WireSize,
        supports_own_wires: SupportsOwnWires,
        phantom: PhantomData<[(); NARGS]>,
    }
    impl<'a, 'b, 'c, 'd, const NARGS: usize> Writer<'a, 'b, 'c, 'd, NARGS> {
        pub(crate) fn add_own_wires(&mut self, delta: WireSize) {
            if matches!(self.supports_own_wires, SupportsOwnWires::OnlyConsumes) {
                panic!("This wire writer was configured for only consuming");
            }
            self.own_wires = self.own_wires.checked_add(delta).unwrap();
        }
        pub(crate) fn write_wires(
            &mut self,
            inputs: [[Wire; NARGS]; BATCH_SIZE],
        ) -> eyre::Result<()> {
            // We'd like to write an array of size (2 * NARGS * BATCH_SIZE), but const generics aren't
            // far enough along for us to do this. As an alternative, we use a multidimentional
            // array as backing storage, and then use bytemuck to turn that array into a slice of
            // the proper format.
            let mut buf_backing = [[[0_u32; 2]; NARGS]; BATCH_SIZE];
            let buf: &mut [u32] = bytemuck::cast_slice_mut(&mut buf_backing);
            debug_assert_eq!(buf.len(), NARGS * BATCH_SIZE * 2);
            for (dst, which_arg) in buf.chunks_exact_mut(BATCH_SIZE * 2).zip(0..NARGS) {
                let wires: [Wire; BATCH_SIZE] = inputs.map(|input| input[which_arg]);
                let (which_inputs, which_wires) = dst.split_at_mut(BATCH_SIZE);
                debug_assert_eq!(which_inputs.len(), BATCH_SIZE);
                debug_assert_eq!(which_wires.len(), BATCH_SIZE);
                for ((which_input, which_wire), wire) in which_inputs
                    .iter_mut()
                    .zip(which_wires.iter_mut())
                    .zip(wires.iter())
                {
                    let max = if let Some(idx) = wire.which_input() {
                        *which_input = idx;
                        self.input_sizes[idx as usize]
                    } else {
                        *which_input = self.input_sizes.len() as u32;
                        self.own_wires
                    };
                    let ww = wire.which_wire();
                    assert!(ww < max);
                    *which_wire = ww;
                }
            }
            self.pb.write_all(bytemuck::cast_slice(buf))?;
            Ok(())
        }
        /// Returns number of own wires
        pub(crate) fn finish(self) -> eyre::Result<WireSize> {
            Ok(self.own_wires)
        }
    }
    #[repr(C)]
    #[derive(Clone, Copy, Debug, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct ReadWire {
        pub which_input: U32x4,
        pub which_wire: U32x4,
    }
    // This iterator should be TrustedLen
    pub fn read<const NARGS: usize>(
        buf: &[U32x4],
    ) -> eyre::Result<impl '_ + Iterator<Item = [ReadWire; NARGS]> + ExactSizeIterator>
    where
        ArrayUnrolledOps: UnrollableArraySize<NARGS>,
    {
        eyre::ensure!(
            buf.len() % (2 * NARGS) == 0,
            "buffer isn't the right size for the batched SIMD wire format"
        );
        Ok(buf.chunks_exact(NARGS * 2).map(|inputs| {
            <[ReadWire; NARGS]>::array_generate(|i| ReadWire {
                which_input: inputs[i * 2],
                which_wire: inputs[i * 2 + 1],
            })
        }))
    }
}

pub type CopyPrototypeWireFormat = simple::WireFormat<(), 1>;
pub type XorPrototypeWireFormat = simple::WireFormat<(), 2>;
pub type Xor4PrototypeWireFormat = simd_batched::WireFormat<2>;
pub type AssertMultiplyPrototypeNoSpecWireFormat = simple::WireFormat<(), 3>;
pub type AssertMultiplyPrototypeSmallBinaryWireFormat = simd_batched::WireFormat<3>;
pub type AssertZeroPrototypeWireFormat = simple::WireFormat<(), 1>;
pub type LinearPrototypeWireFormat<T> = simple::WireFormat<T, 2>;
