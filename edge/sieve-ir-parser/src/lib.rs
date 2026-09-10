#![deny(unused_must_use)]

pub mod fb_reader;
pub mod text_parser;

use std::{io::Write, ops::RangeInclusive, path::Path};

use crypto_bigint::CheckedAdd;

use swanky_error::{ErrorKind, OptionExt, WrapErr};

pub type Identifier<'a> = &'a [u8];
// This needs to be big enough to store all the moduli of all the fields we support
pub type Number = crypto_bigint::U384;

#[derive(Debug, Clone)]
pub enum PluginTypeArg {
    Number(Number),
    String(String),
}

impl PluginTypeArg {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> swanky_error::Result<Self> {
        if s.starts_with("0x") || s.starts_with("0X") {
            let mut out = Number::default();
            for &byte in &s.as_bytes()[2..] {
                out = Option::<_>::from(out.checked_mul(&Number::from_u8(16)))
                    .ok_or_swanky_error(ErrorKind::OtherError, "Number too big.")?;
                let digit = if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte.to_ascii_lowercase() - b'a' + 10
                };
                out = Option::<_>::from(out.checked_add(&Number::from_u8(digit)))
                    .ok_or_swanky_error(ErrorKind::OtherError, "Number too big.")?;
            }
            Ok(PluginTypeArg::Number(out))
        } else if s.starts_with("0o") || s.starts_with("0O") {
            todo!()
        } else if s.chars().all(|c| c.is_numeric()) {
            let mut out = Number::default();
            for &byte in s.as_bytes() {
                if byte.is_ascii_digit() {
                    out = Option::<_>::from(out.checked_mul(&Number::from_u8(10)))
                        .ok_or_swanky_error(ErrorKind::OtherError, "Number too big.")?;
                    out = Option::<_>::from(out.checked_add(&Number::from_u8(byte - b'0')))
                        .ok_or_swanky_error(ErrorKind::OtherError, "Number too big.")?;
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
        modulus: u64,
    },
    Ring {
        nbits: u64,
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
                Type::Ring { nbits } => writeln!(f, "@type ring {nbits};")?,
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

/// A range of wire values, as defined in the SIEVE IR spec.
///
/// Note that this range is _inclusive_; iteration should use
/// [`RangeInclusive`] syntax to account for this.
#[derive(Debug, Clone, Copy)]
pub struct WireRange {
    pub start: WireId,
    pub end: WireId,
}
impl WireRange {
    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }

    pub fn len(&self) -> u64 {
        if self.end >= self.start {
            (self.end - self.start) + 1
        } else {
            0
        }
    }
    pub fn as_single_wire(&self) -> swanky_error::Result<WireId> {
        swanky_error::ensure!(
            self.len() == 1,
            ErrorKind::OtherError,
            "Expected single wire, got a range {}..={}",
            self.start,
            self.end
        );

        Ok(self.start)
    }
    pub fn range(&self) -> RangeInclusive<WireId> {
        self.start..=self.end
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionSemantics {
    NoModulus,
    Modulus,
}

pub trait FunctionBodyVisitor {
    #[allow(clippy::new_ret_no_self, clippy::wrong_self_convention)]
    fn new(&mut self, ty: TypeId, first: WireId, last: WireId) -> swanky_error::Result<()>;
    fn delete(&mut self, ty: TypeId, first: WireId, last: WireId) -> swanky_error::Result<()>;
    fn add(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> swanky_error::Result<()>;
    fn mul(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> swanky_error::Result<()>;
    fn addc(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: &Number,
    ) -> swanky_error::Result<()>;
    fn mulc(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: &Number,
    ) -> swanky_error::Result<()>;
    fn copy(&mut self, ty: TypeId, dst: WireRange, src: &[WireRange]) -> swanky_error::Result<()>;
    fn constant(&mut self, ty: TypeId, dst: WireId, src: &Number) -> swanky_error::Result<()>;
    fn public_input(&mut self, ty: TypeId, dst: WireRange) -> swanky_error::Result<()>;
    fn private_input(&mut self, ty: TypeId, dst: WireRange) -> swanky_error::Result<()>;
    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> swanky_error::Result<()>;
    fn convert(
        &mut self,
        dst: TypedWireRange,
        src: TypedWireRange,
        semantics: ConversionSemantics,
    ) -> swanky_error::Result<()>;
    fn call(
        &mut self,
        dst: &[WireRange],
        name: Identifier,
        args: &[WireRange],
    ) -> swanky_error::Result<()>;
}
pub trait RelationVisitor: FunctionBodyVisitor {
    type FBV<'a>: FunctionBodyVisitor;
    fn define_function<BodyCb>(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: BodyCb,
    ) -> swanky_error::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> swanky_error::Result<()>;
    fn define_plugin_function(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: PluginBinding,
    ) -> swanky_error::Result<()>;
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
    fn write_wire_ranges(&mut self, ranges: &[WireRange]) -> swanky_error::Result<()> {
        for (i, range) in ranges.iter().enumerate() {
            if i != 0 {
                write!(self.0, ",").wrap_err(ErrorKind::OtherError, "Failed to write comma.")?;
            }
            if range.start == range.end {
                write!(self.0, "$0x{:x}", range.start)
                    .wrap_err(ErrorKind::OtherError, "Failed to write single wire.")?;
            } else {
                write!(self.0, "$0x{:x}...$0x{:x}", range.start, range.end)
                    .wrap_err(ErrorKind::OtherError, "Failed to write wire range.")?;
            }
        }
        Ok(())
    }
}
impl<T: Write> FunctionBodyVisitor for PrintingVisitor<T> {
    fn new(&mut self, ty: TypeId, first: WireId, last: WireId) -> swanky_error::Result<()> {
        writeln!(self.0, "@new(0x{ty:x}:$0x{first:x}...$0x{last:x});")
            .wrap_err(ErrorKind::OtherError, "Failed to write 'new' gate.")
    }
    fn delete(&mut self, ty: TypeId, first: WireId, last: WireId) -> swanky_error::Result<()> {
        writeln!(self.0, "@delete(0x{ty:x} : $0x{first:x}...$0x{last:x});")
            .wrap_err(ErrorKind::OtherError, "Failed to write 'delete' gate.")
    }
    fn add(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> swanky_error::Result<()> {
        writeln!(
            self.0,
            "$0x{dst:x} <- @add(0x{ty:x} : $0x{left:x}, $0x{right:x});"
        )
        .wrap_err(ErrorKind::OtherError, "Failed to write 'and' gate.")
    }
    fn mul(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> swanky_error::Result<()> {
        writeln!(
            self.0,
            "$0x{dst:x} <- @mul(0x{ty:x} : $0x{left:x}, $0x{right:x});"
        )
        .wrap_err(ErrorKind::OtherError, "Failed to write 'mul' gate.")
    }
    fn addc(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: &Number,
    ) -> swanky_error::Result<()> {
        writeln!(
            self.0,
            "$0x{dst:x} <- @addc(0x{ty:x} : $0x{left:x}, <{}>);",
            Self::hex(right),
        )
        .wrap_err(ErrorKind::OtherError, "Failed to write 'addc' gate.")
    }
    fn mulc(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: &Number,
    ) -> swanky_error::Result<()> {
        writeln!(
            self.0,
            "$0x{dst:x} <- @mulc(0x{ty:x} : $0x{left:x}, <{}>);",
            Self::hex(right),
        )
        .wrap_err(ErrorKind::OtherError, "Failed to write 'mulc' gate.")
    }
    fn copy(&mut self, ty: TypeId, dst: WireRange, src: &[WireRange]) -> swanky_error::Result<()> {
        self.write_wire_ranges(&[dst])?;
        write!(self.0, " <- 0x{ty:x} : ").wrap_err(
            ErrorKind::OtherError,
            "Failed to write 'copy' gate assignment / type.",
        )?;
        self.write_wire_ranges(src)?;
        writeln!(self.0, ";").wrap_err(ErrorKind::OtherError, "Failed to write semicolon.")
    }
    fn constant(&mut self, ty: TypeId, dst: WireId, src: &Number) -> swanky_error::Result<()> {
        writeln!(self.0, "$0x{dst:x} <- 0x{ty:x} : <{}>;", Self::hex(src))
            .wrap_err(ErrorKind::OtherError, "Failed to write constant.")
    }
    fn public_input(&mut self, ty: TypeId, dst: WireRange) -> swanky_error::Result<()> {
        self.write_wire_ranges(&[dst])?;
        writeln!(self.0, " <- @public(0x{ty:x});")
            .wrap_err(ErrorKind::OtherError, "Failed to write public input.")
    }
    fn private_input(&mut self, ty: TypeId, dst: WireRange) -> swanky_error::Result<()> {
        self.write_wire_ranges(&[dst])?;
        writeln!(self.0, " <- @private(0x{ty:x});")
            .wrap_err(ErrorKind::OtherError, "Failed to write private input.")
    }
    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> swanky_error::Result<()> {
        writeln!(self.0, "@assert_zero(0x{ty:x} : $0x{src:x});")
            .wrap_err(ErrorKind::OtherError, "Failed to write 'assert_zero' gate.")
    }
    fn convert(
        &mut self,
        _dst: TypedWireRange,
        _src: TypedWireRange,
        _semantics: ConversionSemantics,
    ) -> swanky_error::Result<()> {
        todo!()
    }
    fn call(
        &mut self,
        dst: &[WireRange],
        name: Identifier,
        args: &[WireRange],
    ) -> swanky_error::Result<()> {
        if !dst.is_empty() {
            self.write_wire_ranges(dst)?;
            write!(self.0, " <- ")
                .wrap_err(ErrorKind::OtherError, "Failed to write call target arrow.")?;
        }
        write!(
            self.0,
            "@call({}",
            std::str::from_utf8(name).wrap_err(
                ErrorKind::SerializationError,
                "Failed to deserialize name from UTF-8 bytes."
            )?
        )
        .wrap_err(ErrorKind::OtherError, "Failed to write 'call' gate.")?;
        if !args.is_empty() {
            write!(self.0, ", ").wrap_err(ErrorKind::OtherError, "Failed to write comma.")?;
            self.write_wire_ranges(args)?;
        }
        writeln!(self.0, ");")
            .wrap_err(ErrorKind::OtherError, "Failed to write paren / semicolon.")?;
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
    ) -> swanky_error::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> swanky_error::Result<()>,
    {
        write!(
            self.0,
            "@function({}",
            std::str::from_utf8(name)
                .wrap_err(ErrorKind::SerializationError, "Function name isn't UTF-8.")?
        )
        .wrap_err(
            ErrorKind::OtherError,
            "Failed to write start of function declaration.",
        )?;
        for (name, arr) in [("out", outputs), ("in", inputs)] {
            if !arr.is_empty() {
                write!(self.0, ", @{name}:")
                    .wrap_err(ErrorKind::OtherError, "Failed to write name.")?;
                for (i, entry) in arr.iter().enumerate() {
                    if i != 0 {
                        write!(self.0, ",")
                            .wrap_err(ErrorKind::OtherError, "Failed to write comma.")?;
                    }
                    write!(self.0, "0x{:x}:0x{:x}", entry.ty, entry.count)
                        .wrap_err(ErrorKind::OtherError, "Failed to write wire counts.")?;
                }
            }
        }
        writeln!(self.0, ")").wrap_err(ErrorKind::OtherError, "Failed to write close paren.")?;
        body(self)?;
        writeln!(self.0, "@end").wrap_err(ErrorKind::OtherError, "Failed to write '@end'.")?;
        Ok(())
    }

    // TODO: Worth addressing the duplicate logic in here?
    fn define_plugin_function(
        &mut self,
        name: Identifier,
        outputs: &[TypedCount],
        inputs: &[TypedCount],
        body: PluginBinding,
    ) -> swanky_error::Result<()> {
        write!(
            self.0,
            "@function({}",
            std::str::from_utf8(name)
                .wrap_err(ErrorKind::SerializationError, "Function name isn't UTF-8.")?
        )
        .wrap_err(ErrorKind::OtherError, "Failed to write function name.")?;
        for (name, arr) in [("out", outputs), ("in", inputs)] {
            if !arr.is_empty() {
                write!(self.0, ", @{name}:")
                    .wrap_err(ErrorKind::OtherError, "Failed to write 'out' or 'in'.")?;
                for (i, entry) in arr.iter().enumerate() {
                    if i != 0 {
                        write!(self.0, ",")
                            .wrap_err(ErrorKind::OtherError, "Failed to write comma.")?;
                    }
                    write!(self.0, "0x{:x}:0x{:x}", entry.ty, entry.count)
                        .wrap_err(ErrorKind::OtherError, "Failed to write wire type / count.")?;
                }
            }
        }
        writeln!(self.0, ")").wrap_err(ErrorKind::OtherError, "Failed to write close paren.")?;

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

        write!(self.0, "  @plugin({}, {}", name, operation)
            .wrap_err(ErrorKind::OtherError, "Failed to write plugin declaration.")?;
        if !args.is_empty() {
            write!(self.0, ", ").wrap_err(ErrorKind::OtherError, "Failed to write comma.")?;
            for (i, arg) in args.iter().enumerate() {
                if i != 0 {
                    write!(self.0, ",")
                        .wrap_err(ErrorKind::OtherError, "Failed to write comma.")?;
                }
                match arg {
                    PluginTypeArg::Number(n) => write!(self.0, "0x{n:x}").wrap_err(
                        ErrorKind::OtherError,
                        "Failed to write plugin number argument.",
                    )?,
                    PluginTypeArg::String(s) => write!(self.0, "{s}").wrap_err(
                        ErrorKind::OtherError,
                        "Failed to write plugin string argument.",
                    )?,
                }
            }
        }
        for (name, arr) in [("private", private_counts), ("public", public_counts)] {
            if !arr.is_empty() {
                write!(self.0, ", @{name}:").wrap_err(
                    ErrorKind::OtherError,
                    "Failed to write 'private' or 'public'.",
                )?;
                for (i, entry) in arr.iter().enumerate() {
                    if i != 0 {
                        write!(self.0, ",")
                            .wrap_err(ErrorKind::OtherError, "Failed to write comma.")?;
                    }
                    write!(self.0, "0x{:x}:0x{:x}", entry.ty, entry.count).wrap_err(
                        ErrorKind::OtherError,
                        "Failed to write private / public type / count.",
                    )?;
                }
            }
        }
        writeln!(self.0, ")").wrap_err(ErrorKind::OtherError, "Failed to write close paren.")?;

        Ok(())
    }
}

pub trait ValueStreamReader: Sized {
    fn open(kind: ValueStreamKind, path: &Path) -> swanky_error::Result<Self>;
    fn modulus(&self) -> &Number;
    fn next(&mut self) -> swanky_error::Result<Option<Number>>;
}
pub trait RelationReader: Sized {
    fn open(path: &Path) -> swanky_error::Result<Self>;
    fn header(&self) -> &Header;
    fn read(self, rv: &mut impl RelationVisitor) -> swanky_error::Result<()>;
}
