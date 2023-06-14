use bytemuck::Zeroable;
use eyre::WrapErr;
use mac_n_cheese_vole::specialization::{
    FiniteFieldSpecialization, NoSpecialization, SmallBinaryFieldSpecialization,
};
use rustc_hash::FxHashMap;
use scuttlebutt::field::{F128p, F61p, F63b, FiniteField, IsSubFieldOf, SmallBinaryField, F2};
use std::{
    any::{type_name, TypeId},
    fs::File,
    hash::BuildHasherDefault,
    io::{Read, Seek},
    os::unix::prelude::FileExt,
    sync::atomic::AtomicU32,
};

use crate::MAC_N_CHEESE_VERSION;

use self::fb::DataChunkAddress;

pub type NumericalEnumType = u16;

trait NumericalEnum: TryFrom<NumericalEnumType> + Into<NumericalEnumType> {
    const BITS: NumericalEnumType;
}

macro_rules! numerical_enum {
    (@helper $name:ident :: $variant:ident $dident:ident $data:ty) => {
        $name::$variant($dident)
    };
    (@helper $name:ident :: $variant:ident $dident:ident) => {
        $name::$variant
    };
    (@helper $data:ty) => {($data)};
    (
        #[test_module($test_module:ident)]
        pub enum $name:ident {$(
            $variant:ident
            $(($data:ty))?
        ),*$(,)?}
    ) => {
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
        pub enum $name {
            $($variant$(($data))?),*
        }
        impl $name {
            const NUM_VARIANTS: NumericalEnumType =
                0 $(+ {
                    let _ = stringify!($variant);
                    1
                })*;
            const VARIANT_BITS: NumericalEnumType =
                (NumericalEnumType::BITS - Self::NUM_VARIANTS.leading_zeros()) as NumericalEnumType;
            const DATA_BITS: NumericalEnumType = {
                let mut acu = 0;
                $(
                    let _ = stringify!($variant);
                    $(
                        let x = <$data as NumericalEnum>::BITS;
                        if acu < x {
                            acu = x;
                        }
                    )?
                )*
                acu = acu; // Silence warning
                acu
            };
        }
        impl NumericalEnum for $name {
            const BITS: NumericalEnumType =
                Self::VARIANT_BITS + Self::DATA_BITS;
        }
        impl From<$name> for NumericalEnumType {
            #[allow(non_snake_case)]
            fn from(x: $name) -> NumericalEnumType {
                let mut acu: NumericalEnumType = 0;
                $(
                    if let numerical_enum!(@helper $name::$variant data $($data)?) = x {
                        return (acu << $name::DATA_BITS) $(
                            | {
                                let data: $data = data;
                                let out: NumericalEnumType = data.into();
                                out
                            }
                        )?;
                    }
                    acu += 1;
                )*
                let _ = acu; // Silence warning
                unreachable!()
            }
        }
        impl TryFrom<NumericalEnumType> for $name {
            type Error = eyre::Report;

            fn try_from(x: NumericalEnumType) -> eyre::Result<Self> {
                let kind = x >> Self::DATA_BITS;
                let mut acu = 0;
                $(
                    if acu == kind {
                        return Ok($name::$variant $(({
                            let data_bits = x & ((1 << Self::DATA_BITS) - 1);
                            let data = <$data>::try_from(data_bits)
                                .wrap_err_with(|| format!(
                                    "Parsing {} data for {}::{}",
                                    std::any::type_name::<$data>(),
                                    std::any::type_name::<$name>(),
                                    stringify!($name)
                                ))?;
                            data
                        }))?);
                    }
                    acu += 1;
                )*
                let _ = acu;  // Silence warning
                eyre::bail!("Unknown discriminant {kind} for {}", std::any::type_name::<Self>());
            }
        }
        #[cfg(test)]
        mod $test_module {
            use super::*;
            use proptest::prelude::*;
            #[test]
            fn num_bits_not_too_big() {
                assert!(<$name as NumericalEnum>::BITS <= 32);
            }
            impl Arbitrary for $name {
                type Parameters = ();
                type Strategy = BoxedStrategy<Self>;

                #[allow(unused_parens, non_snake_case)]
                fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
                    (
                        0..$name::NUM_VARIANTS,
                        any::<($(
                            ($($data)?),
                        )*)>(),
                    ).prop_map(|(variant, (
                        $($variant,)*
                    ))| {
                        let mut acu = 0;
                        $(
                            let _ = $variant; // silence unused variable warning
                            if acu == variant {
                                return $name::$variant$(({
                                    let x: $data = $variant;
                                    x
                                }))?;
                            }
                            acu += 1;
                        )*
                        let _ = acu;
                        unreachable!()
                    }).boxed()
                }
            }
            proptest! {
                #[test]
                fn serialize_roundtrip(x in any::<$name>()) {
                    let num: NumericalEnumType = x.into();
                    prop_assert_eq!($name::try_from(num).unwrap(), x);
                }
            }
        }
    };
}

numerical_enum! {
    #[test_module(task_kind_test)]
    pub enum TaskKind {
        Constant(FieldMacType),
        Fix(FieldMacType),
        Copy(Type),
        Add(FieldMacType),
        Xor4(FieldMacType),
        Linear(FieldMacType),
        AssertZero(FieldMacType),
        AssertMultiplication(FieldMacType),
        BaseSvole(FieldMacType),
        VoleExtension(FieldMacType),
    }
}

pub trait FieldTypeMacVisitor: Sized {
    type Output;
    fn visit_small_binary<TF: SmallBinaryField>(self) -> Self::Output
    where
        F2: IsSubFieldOf<TF>,
    {
        self.visit::<F2, TF, SmallBinaryFieldSpecialization>()
    }
    fn visit<
        VF: FiniteField + IsSubFieldOf<TF>,
        TF: FiniteField,
        S: FiniteFieldSpecialization<VF, TF>,
    >(
        self,
    ) -> Self::Output;
}

macro_rules! field_mac_type {
    (@visithelper ($v:expr) NoSpecialization, $VF:ty, $TF:ty) => {$v.visit::<$VF, $TF, NoSpecialization>()};
    (@visithelper ($v:expr) SmallBinaryFieldSpecialization, $TF:ty) => {$v.visit_small_binary::<$TF>()};
    (@gethelper NoSpecialization, $VF:ty, $TF:ty) => {(TypeId::of::<$VF>(), TypeId::of::<$TF>())};
    (@gethelper SmallBinaryFieldSpecialization, $TF:ty) => {(TypeId::of::<F2>(), TypeId::of::<$TF>())};
    (
        $($name:ident<$kind:ident, $($ty:ty),*>,)*
    ) => {
        numerical_enum! {
            #[test_module(field_mac_type_test)]
            pub enum FieldMacType {
                $($name,)*
            }
        }
        impl FieldMacType {
            pub const ALL: &[FieldMacType] = &[$(FieldMacType::$name),*];
            pub fn visit<V: FieldTypeMacVisitor>(&self, v: V) -> V::Output {
                match self {
                    $(
                        FieldMacType::$name =>
                            field_mac_type!(@visithelper (v) $kind, $($ty),*),
                    )*
                }
            }
            pub fn visit_all<V>(mut v: V)
                where for<'a> &'a mut V: FieldTypeMacVisitor<Output = ()>
            {
                $(
                    field_mac_type!(@visithelper (&mut v) $kind, $($ty),*);
                )*
            }

            pub fn get_opt<VF: FiniteField + IsSubFieldOf<TF>, TF: FiniteField>() -> Option<Self> {
                let vf = TypeId::of::<VF>();
                let tf = TypeId::of::<TF>();
                $(
                    if (vf, tf) == field_mac_type!(@gethelper $kind, $($ty),*) {
                        return Some(FieldMacType::$name);
                    }
                )*
                None
            }
        }
    };
}
field_mac_type! {
    BinaryF63b<SmallBinaryFieldSpecialization, F63b>,
    F63b<NoSpecialization, F63b, F63b>,
    F61p<NoSpecialization, F61p, F61p>,
    F128p<NoSpecialization, F128p, F128p>,
}

#[test]
fn no_field_is_registered_twice() {
    use rustc_hash::FxHashSet;
    let mut seen_types = FxHashSet::<(TypeId, TypeId)>::default();
    struct V<'a>(&'a mut FxHashSet<(TypeId, TypeId)>);
    impl FieldTypeMacVisitor for &'_ mut V<'_> {
        type Output = ();
        fn visit<
            VF: FiniteField + IsSubFieldOf<TF>,
            TF: FiniteField,
            S: FiniteFieldSpecialization<VF, TF>,
        >(
            self,
        ) -> Self::Output {
            // We intentionally don't include the specialization in the tuple, since it is an
            // error to include the same pair twice, even if it's with a different specialization
            // each time.
            assert!(
                self.0.insert((TypeId::of::<VF>(), TypeId::of::<TF>())),
                "Mac type appears multiple time in field list {:?}",
                std::any::type_name::<(VF, TF)>()
            );
        }
    }
    FieldMacType::visit_all::<V>(V(&mut seen_types));
}

#[test]
fn all_prime_fields_are_registered() {
    struct V;
    impl FieldTypeMacVisitor for &'_ mut V {
        type Output = ();
        fn visit<
            VF: FiniteField + IsSubFieldOf<TF>,
            TF: FiniteField,
            S: FiniteFieldSpecialization<VF, TF>,
        >(
            self,
        ) {
            // This will panic if the prime field isn't registered.
            FieldMacType::get::<VF, TF>().prime_field_type();
        }
    }
    FieldMacType::visit_all::<V>(V);
}

impl FieldMacType {
    pub fn get<VF: FiniteField + IsSubFieldOf<TF>, TF: FiniteField>() -> Self {
        if let Some(out) = Self::get_opt::<VF, TF>() {
            out
        } else {
            panic!(
                "FieldMacType::get::<{}, {}>() doesn't exist",
                type_name::<VF>(),
                type_name::<TF>()
            );
        }
    }

    /// Return a `FieldMacType` with the same tag field as `Self` and where the value field is the
    /// prime subfield of the tag field.
    pub fn prime_field_type(&self) -> Self {
        struct V;
        impl FieldTypeMacVisitor for V {
            type Output = FieldMacType;
            fn visit<
                VF: FiniteField + IsSubFieldOf<TF>,
                TF: FiniteField,
                S: FiniteFieldSpecialization<VF, TF>,
            >(
                self,
            ) -> Self::Output {
                FieldMacType::get::<TF::PrimeField, TF>()
            }
        }
        self.visit(V)
    }

    pub fn assert_value_field_is<FE: FiniteField>(&self) {
        struct V(TypeId, &'static str);
        impl FieldTypeMacVisitor for V {
            type Output = ();
            fn visit<
                VF: FiniteField + IsSubFieldOf<TF>,
                TF: FiniteField,
                S: FiniteFieldSpecialization<VF, TF>,
            >(
                self,
            ) -> Self::Output {
                assert_eq!(
                    TypeId::of::<VF>(),
                    self.0,
                    "{} != {}",
                    self.1,
                    std::any::type_name::<VF>()
                );
            }
        }
        self.visit(V(TypeId::of::<FE>(), std::any::type_name::<FE>()));
    }

    pub fn uses_small_binary_specialization(&self) -> bool {
        struct V;
        impl FieldTypeMacVisitor for V {
            type Output = bool;
            fn visit_small_binary<TF: SmallBinaryField>(self) -> Self::Output
            where
                F2: IsSubFieldOf<TF>,
            {
                true
            }
            fn visit<
                VF: FiniteField + IsSubFieldOf<TF>,
                TF: FiniteField,
                S: FiniteFieldSpecialization<VF, TF>,
            >(
                self,
            ) -> Self::Output {
                false
            }
        }
        self.visit(V)
    }
}

numerical_enum! {
    #[test_module(type_test)]
    pub enum Type {
        // Technically a RandomMac is a subtype of a Mac, but I don't think we'll ever need to take
        // advantage of that fact.
        RandomMac(FieldMacType),
        Mac(FieldMacType),
    }
}

pub type GraphDegreeCount = u32;
pub type AtomicGraphDegreeCount = AtomicU32;
#[test]
fn atomic_graph_degree_count_matches_non_atomic() {
    assert_eq!(
        std::mem::size_of::<GraphDegreeCount>(),
        std::mem::size_of::<AtomicGraphDegreeCount>()
    );
    assert_eq!(
        std::mem::align_of::<GraphDegreeCount>(),
        std::mem::align_of::<AtomicGraphDegreeCount>()
    );
}

// Keep these type aliases in sync with compilation_format.fbs
pub type TaskPrototypeId = u32;
pub type TaskOutputIndex = u32;
pub type TaskPriority = i32;
pub type TaskId = u32;
pub type WireSize = u32;

/// The generated flatbuffers structures.
#[path = "compilation_format_generated.rs"]
pub mod fb;

impl From<Type> for fb::Type {
    fn from(value: Type) -> Self {
        Self::new(value.into())
    }
}
impl TryFrom<fb::Type> for Type {
    type Error = eyre::Report;

    fn try_from(value: fb::Type) -> Result<Self, Self::Error> {
        value.encoding().try_into()
    }
}
impl fb::TaskPrototype<'_> {
    pub fn kind(&self) -> eyre::Result<TaskKind> {
        self.kind_encoding().try_into().context("Invalid task kind")
    }
}

pub type ManifestHash = u64;

pub struct Manifest {
    buffer: Vec<u8>,
    hash: ManifestHash,
    file: File,
}
impl Manifest {
    pub fn read(mut f: File) -> eyre::Result<Self> {
        f.seek(std::io::SeekFrom::End(-8 * 4))?;
        let mut footer = [0_u64; 4];
        f.read_exact(bytemuck::bytes_of_mut(&mut footer))?;
        let [manifest_start, manifest_decompressed_len, manifest_hash, version] = footer;
        eyre::ensure!(
            version == MAC_N_CHEESE_VERSION,
            "Manifest has version {version}, not {MAC_N_CHEESE_VERSION}"
        );
        let manifest_decompressed_len = usize::try_from(manifest_decompressed_len)
            .context("manifest size is too big for usize")?;
        f.seek(std::io::SeekFrom::Start(manifest_start))?;
        let mut decompressor = lz4::Decoder::new(&mut f)?;
        let mut buffer = vec![0; manifest_decompressed_len];
        decompressor.read_exact(&mut buffer)?;
        let n = decompressor.read(&mut [0_u8])?;
        eyre::ensure!(n == 0, "Should have hit LZ4 EOF");
        decompressor.finish().1?;
        let _validated_root = fb::root_as_manifest(&buffer)?;
        Ok(Self {
            hash: manifest_hash,
            buffer,
            file: f,
        })
    }
    pub fn hash(&self) -> u64 {
        self.hash
    }
    pub fn manifest(&self) -> fb::Manifest {
        unsafe {
            // SAFETY: the buffer was validated on construction
            fb::root_as_manifest_unchecked(&self.buffer)
        }
    }
    pub fn read_data_chunk(&self, chunk: &DataChunkAddress, dst: &mut [u8]) -> eyre::Result<()> {
        assert_eq!(chunk.length() as usize, dst.len());
        read_data_chunk(&self.file, chunk.start(), chunk.compressed_length(), dst)
    }
}
fn read_data_chunk(
    file: &File,
    start: u64,
    compressed_len: u32,
    dst: &mut [u8],
) -> eyre::Result<()> {
    if dst.is_empty() {
        return Ok(());
    }
    struct Adapter<'a> {
        file: &'a File,
        pos: u64,
        end: u64,
    }
    impl Read for Adapter<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            debug_assert!(self.pos <= self.end);
            let to_take = (self.end - self.pos).min(buf.len() as u64) as usize;
            let n = self.file.read_at(&mut buf[0..to_take], self.pos)?;
            self.pos += n as u64;
            debug_assert!(self.pos <= self.end);
            Ok(n)
        }
    }
    let mut d = lz4::Decoder::new(Adapter {
        file,
        pos: start,
        end: start + u64::from(compressed_len),
    })?;
    d.read_exact(dst)?;
    Ok(())
}

#[test]
fn test_read_data_chunk() {
    for size in [0, 1, 64, 1024 * 1024] {
        dbg!(size);
        use std::io::Write;
        let f = tempfile::tempfile().unwrap();
        // To help weed out bugs, we apply an offset before we start writing.
        let mut buf_f = std::io::BufWriter::new(f);
        buf_f.write_all(&vec![7; 745]).unwrap();
        let chunk = super::circuit_builder::write_data_chunk(&mut buf_f, |mut dcw| {
            dcw.write_all(&vec![15; size])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(chunk.length(), size as u32);
        let f = buf_f.into_inner().unwrap();
        let mut dst = vec![0; size];
        read_data_chunk(&f, chunk.start(), chunk.compressed_length(), &mut dst).unwrap();
        assert_eq!(dst, vec![15; size]);
    }
}

#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub(crate) struct PrivatesManifestEntry {
    pub(crate) offset: u64,
    pub(crate) length: u32,
    pub(crate) task_id: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PrivateDataAddress {
    pub offset: u64,
    pub len: u32,
}

pub type PrivatesManifest = FxHashMap<TaskId, PrivateDataAddress>;
pub fn read_private_manifest(f: &mut File) -> eyre::Result<PrivatesManifest> {
    let mut pos = 0_u64;
    f.seek(std::io::SeekFrom::End(-8))?;
    f.read_exact(bytemuck::bytes_of_mut(&mut pos))?;
    f.seek(std::io::SeekFrom::Start(pos))?;
    let mut count = 0_u32;
    f.read_exact(bytemuck::bytes_of_mut(&mut count))?;
    let mut out =
        FxHashMap::with_capacity_and_hasher(count as usize, BuildHasherDefault::default());
    let mut entry = PrivatesManifestEntry::zeroed();
    for _ in 0..count {
        f.read_exact(bytemuck::bytes_of_mut(&mut entry))?;
        let old = out.insert(
            entry.task_id,
            PrivateDataAddress {
                offset: entry.offset,
                len: entry.length,
            },
        );
        eyre::ensure!(old.is_none(), "private entry for task was duplicated");
    }
    Ok(out)
}

pub mod wire_format;
