#![deny(unused_must_use)]

pub mod fb_reader;
pub mod text_parser;

use std::{io::Write, path::Path};

use crypto_bigint::{CheckedAdd, CheckedMul};

use eyre::{Context, ContextCompat};

pub type Identifier<'a> = &'a [u8];
// This needs to be big enough to store all the moduli of all the fields we support
pub type Number = crypto_bigint::U384;

#[derive(Debug, Clone)]
pub enum PluginTypeArg {
    Number(Number),
    String(String),
}

impl PluginTypeArg {
    pub fn from_str(s: &str) -> eyre::Result<Self> {
        if s.starts_with("0x") || s.starts_with("0X") {
            Ok(PluginTypeArg::Number(Number::from_be_hex(&s[2..])))
        } else if s.starts_with("0o") || s.starts_with("0O") {
            todo!()
        } else if s.chars().all(|c| c.is_numeric()) {
            let mut out = Number::default();
            for &byte in s.as_bytes() {
                if byte.is_ascii_digit() {
                    out = Option::<_>::from(out.checked_mul(&Number::from_u8(10)))
                        .context("number too big")?;
                    out = Option::<_>::from(out.checked_add(&Number::from_u8(byte - b'0')))
                        .context("number too big")?;
                }
            }
            Ok(PluginTypeArg::Number(out))
        } else {
            Ok(PluginTypeArg::String(String::from(s)))
        }
    }
}

#[derive(Debug, Clone)]
pub struct PluginType {
    pub name: String,
    pub operation: String,
    pub args: Vec<PluginTypeArg>,
}

#[derive(Debug, Clone)]
pub struct PluginBinding {
    pub plugin_type: PluginType,
    pub private_counts: Vec<TypedCount>,
    pub public_counts: Vec<TypedCount>,
}

#[derive(Debug, Clone)]
pub enum Type {
    Field {
        modulus: Number,
    },
    ExtField {
        index: TypeId,
        degree: u64,
        modulus: Number,
    },
    // Ignores private/public counts in this context, but they're needed
    // for plugin function bodies
    PluginType(PluginType),
}

/// The type index.
// The maximum number of types is 256, hence we use `u8` here.
pub type TypeId = u8;
pub type WireId = u64;

#[derive(Debug, Clone, Copy)]
pub struct TypedCount {
    pub ty: TypeId,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct ConversionDescription {
    pub output: TypedCount,
    pub input: TypedCount,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub plugins: Vec<String>,
    pub types: Vec<Type>,
    pub conversion: Vec<ConversionDescription>,
}
impl std::fmt::Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "version 2.0.0;")?;
        writeln!(f, "circuit;")?;

        for plugin in self.plugins.iter() {
            writeln!(f, "@plugin {};", plugin)?;
        }

        for ty in self.types.iter() {
            match ty {
                Type::Field { modulus } => writeln!(f, "@type field 0x{modulus:X};")?,
                Type::ExtField {
                    index,
                    degree,
                    modulus,
                } => writeln!(f, "@type ext_field {index} {degree} {modulus}")?,
                Type::PluginType(PluginType {
                    name,
                    operation,
                    args,
                }) => {
                    write!(f, "@type @plugin({}, {}", name, operation)?;
                    if !args.is_empty() {
                        write!(f, ", ")?;
                        for (i, arg) in args.iter().enumerate() {
                            if i != 0 {
                                write!(f, ", ")?;
                            }
                            match arg {
                                PluginTypeArg::Number(n) => write!(f, "0x{n:X}")?,
                                PluginTypeArg::String(s) => write!(f, "{}", s)?,
                            }
                        }
                    }
                    writeln!(f, ");")?;
                }
            }
        }
        for cd in self.conversion.iter() {
            writeln!(
                f,
                "@convert 0x{:x} : 0x{:x} , 0x{:X} : 0x{:X}",
                cd.output.ty, cd.output.count, cd.input.ty, cd.input.count
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WireRange {
    pub start: WireId,
    pub end: WireId,
}
impl WireRange {
    pub fn len(&self) -> u64 {
        if self.end >= self.start {
            (self.end - self.start) + 1
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TypedWireRange {
    pub ty: TypeId,
    pub range: WireRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueStreamKind {
    Public,
    Private,
}

pub trait FunctionBodyVisitor {
    fn new(&mut self, ty: TypeId, first: WireId, last: WireId) -> eyre::Result<()>;
    fn delete(&mut self, ty: TypeId, first: WireId, last: WireId) -> eyre::Result<()>;
    fn add(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()>;
    fn mul(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()>;
    fn addc(&mut self, ty: TypeId, dst: WireId, left: WireId, right: &Number) -> eyre::Result<()>;
    fn mulc(&mut self, ty: TypeId, dst: WireId, left: WireId, right: &Number) -> eyre::Result<()>;
    fn copy(&mut self, ty: TypeId, dst: WireId, src: WireId) -> eyre::Result<()>;
    fn constant(&mut self, ty: TypeId, dst: WireId, src: &Number) -> eyre::Result<()>;
    fn public_input(&mut self, ty: TypeId, dst: WireId) -> eyre::Result<()>;
    fn private_input(&mut self, ty: TypeId, dst: WireId) -> eyre::Result<()>;
    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> eyre::Result<()>;
    fn convert(&mut self, dst: TypedWireRange, src: TypedWireRange) -> eyre::Result<()>;
    fn call(&mut self, dst: &[WireRange], name: Identifier, args: &[WireRange])
        -> eyre::Result<()>;
}
pub trait RelationVisitor: FunctionBodyVisitor {
    type FBV<'a>: FunctionBodyVisitor;
    fn define_function<BodyCb>(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: BodyCb,
    ) -> eyre::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> eyre::Result<()>;
    fn define_plugin_function(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: PluginBinding,
    ) -> eyre::Result<()>;
}

pub struct PrintingVisitor<T: Write>(pub T);
impl<T: Write> PrintingVisitor<T> {
    fn hex(n: &Number) -> impl std::fmt::Display + '_ {
        struct Hex<'a>(&'a Number);
        impl std::fmt::Display for Hex<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "0x")?;
                let mut limbs = self.0.as_limbs().iter().rev().skip_while(|x| x.0 == 0);
                if let Some(most_significant) = limbs.next() {
                    write!(f, "{:x}", most_significant.0)?;
                    for limb in limbs {
                        // The limb is zero padded
                        write!(f, "{:x}", limb)?;
                    }
                } else {
                    write!(f, "0")?;
                }
                Ok(())
            }
        }
        Hex(n)
    }
    fn write_wire_ranges(&mut self, ranges: &[WireRange]) -> eyre::Result<()> {
        for (i, range) in ranges.iter().enumerate() {
            if i != 0 {
                write!(self.0, ",")?;
            }
            if range.start == range.end {
                write!(self.0, "$0x{:x}", range.start)?;
            } else {
                write!(self.0, "$0x{:x}...$0x{:x}", range.start, range.end)?;
            }
        }
        Ok(())
    }
}
impl<T: Write> FunctionBodyVisitor for PrintingVisitor<T> {
    fn new(&mut self, ty: TypeId, first: WireId, last: WireId) -> eyre::Result<()> {
        Ok(writeln!(
            self.0,
            "@new(0x{ty:x}:$0x{first:x}...$0x{last:x});"
        )?)
    }
    fn delete(&mut self, ty: TypeId, first: WireId, last: WireId) -> eyre::Result<()> {
        Ok(writeln!(
            self.0,
            "@delete(0x{ty:x} : $0x{first:x}...$0x{last:x});"
        )?)
    }
    fn add(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()> {
        Ok(writeln!(
            self.0,
            "$0x{dst:x} <- @add(0x{ty:x} : $0x{left:x}, $0x{right:x});"
        )?)
    }
    fn mul(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()> {
        Ok(writeln!(
            self.0,
            "$0x{dst:x} <- @mul(0x{ty:x} : $0x{left:x}, $0x{right:x});"
        )?)
    }
    fn addc(&mut self, ty: TypeId, dst: WireId, left: WireId, right: &Number) -> eyre::Result<()> {
        Ok(writeln!(
            self.0,
            "$0x{dst:x} <- @addc(0x{ty:x} : $0x{left:x}, <{}>);",
            Self::hex(right),
        )?)
    }
    fn mulc(&mut self, ty: TypeId, dst: WireId, left: WireId, right: &Number) -> eyre::Result<()> {
        Ok(writeln!(
            self.0,
            "$0x{dst:x} <- @mulc(0x{ty:x} : $0x{left:x}, <{}>);",
            Self::hex(right),
        )?)
    }
    fn copy(&mut self, ty: TypeId, dst: WireId, src: WireId) -> eyre::Result<()> {
        Ok(writeln!(self.0, "$0x{dst:x} <- 0x{ty:x} : $0x{src:x};")?)
    }
    fn constant(&mut self, ty: TypeId, dst: WireId, src: &Number) -> eyre::Result<()> {
        Ok(writeln!(
            self.0,
            "$0x{dst:x} <- 0x{ty:x} : <{}>;",
            Self::hex(src)
        )?)
    }
    fn public_input(&mut self, ty: TypeId, dst: WireId) -> eyre::Result<()> {
        Ok(writeln!(self.0, "$0x{dst:x} <- @public(0x{ty:x});")?)
    }
    fn private_input(&mut self, ty: TypeId, dst: WireId) -> eyre::Result<()> {
        Ok(writeln!(self.0, "$0x{dst:x} <- @private(0x{ty:x});")?)
    }
    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> eyre::Result<()> {
        Ok(writeln!(self.0, "@assert_zero(0x{ty:x} : $0x{src:x});")?)
    }
    fn convert(&mut self, _dst: TypedWireRange, _src: TypedWireRange) -> eyre::Result<()> {
        todo!()
    }
    fn call(
        &mut self,
        dst: &[WireRange],
        name: Identifier,
        args: &[WireRange],
    ) -> eyre::Result<()> {
        if !dst.is_empty() {
            self.write_wire_ranges(dst)?;
            write!(self.0, " <- ")?;
        }
        write!(self.0, "@call({}", std::str::from_utf8(name)?)?;
        if !args.is_empty() {
            write!(self.0, ", ")?;
            self.write_wire_ranges(args)?;
        }
        writeln!(self.0, ");")?;
        Ok(())
    }
}
impl<T: Write> RelationVisitor for PrintingVisitor<T> {
    type FBV<'a> = Self;

    fn define_function<BodyCb>(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: BodyCb,
    ) -> eyre::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> eyre::Result<()>,
    {
        write!(
            self.0,
            "@function({}",
            std::str::from_utf8(name).context("function name isn't utf-8")?
        )?;
        for (name, arr) in [("out", outputs), ("in", inputs)] {
            if !arr.is_empty() {
                write!(self.0, ", @{name}:")?;
                for (i, entry) in arr.iter().enumerate() {
                    if i != 0 {
                        write!(self.0, ",")?;
                    }
                    write!(self.0, "0x{:x}:0x{:x}", entry.ty, entry.count)?;
                }
            }
        }
        writeln!(self.0, ")")?;
        body(self)?;
        writeln!(self.0, "@end")?;
        Ok(())
    }

    // TODO: Worth addressing the duplicate logic in here?
    fn define_plugin_function(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: PluginBinding,
    ) -> eyre::Result<()> {
        write!(
            self.0,
            "@function({}",
            std::str::from_utf8(name).context("function name isn't utf-8")?
        )?;
        for (name, arr) in [("out", outputs), ("in", inputs)] {
            if !arr.is_empty() {
                write!(self.0, ", @{name}:")?;
                for (i, entry) in arr.iter().enumerate() {
                    if i != 0 {
                        write!(self.0, ",")?;
                    }
                    write!(self.0, "0x{:x}:0x{:x}", entry.ty, entry.count)?;
                }
            }
        }
        writeln!(self.0, ")")?;

        let PluginBinding {
            plugin_type:
                PluginType {
                    name,
                    operation,
                    args,
                },
            private_counts,
            public_counts,
        } = body;

        write!(self.0, "  @plugin({}, {}", name, operation)?;
        if !args.is_empty() {
            write!(self.0, ", ")?;
            for (i, arg) in args.iter().enumerate() {
                if i != 0 {
                    write!(self.0, ",")?;
                }
                match arg {
                    PluginTypeArg::Number(n) => write!(self.0, "0x{n:x}")?,
                    PluginTypeArg::String(s) => write!(self.0, "{s}")?,
                }
            }
        }
        for (name, arr) in [("private", private_counts), ("public", public_counts)] {
            if !arr.is_empty() {
                write!(self.0, ", @{name}:")?;
                for (i, entry) in arr.iter().enumerate() {
                    if i != 0 {
                        write!(self.0, ",")?;
                    }
                    write!(self.0, "0x{:x}:0x{:x}", entry.ty, entry.count)?;
                }
            }
        }
        writeln!(self.0, ")")?;

        Ok(())
    }
}

pub trait ValueStreamReader: Sized {
    fn open(kind: ValueStreamKind, path: &Path) -> eyre::Result<Self>;
    fn modulus(&self) -> &Number;
    fn next(&mut self) -> eyre::Result<Option<Number>>;
}
pub trait RelationReader: Sized {
    fn open(path: &Path) -> eyre::Result<Self>;
    fn header(&self) -> &Header;
    fn read(self, rv: &mut impl RelationVisitor) -> eyre::Result<()>;
}
